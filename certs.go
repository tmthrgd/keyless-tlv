package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/gokeyless"
)

type cert struct {
	leaf *x509.Certificate
	pem  []byte
}

type sortSKIs struct {
	skis []gokeyless.SKI
	cert map[gokeyless.SKI]cert
}

func (s sortSKIs) Len() int {
	return len(s.skis)
}

func (s sortSKIs) Less(i, j int) bool {
	a := s.cert[s.skis[i]].leaf
	b := s.cert[s.skis[j]].leaf

	/* shift ecdsa keys to the start */
	switch a.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		switch b.SignatureAlgorithm {
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		default:
			return true
		}
	}

	if pubA, ok := a.PublicKey.(*ecdsa.PublicKey); ok {
		if pubB, ok := b.PublicKey.(*ecdsa.PublicKey); ok {
			switch pubA.Curve {
			case elliptic.P521():
				switch pubB.Curve {
				case elliptic.P384(),
					elliptic.P256():
					return true
				}
			case elliptic.P384():
				switch pubB.Curve {
				case elliptic.P256():
					return true
				}
			case elliptic.P256():
			default:
				panic("not supported")
			}
		}
	}

	switch a.SignatureAlgorithm {
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		switch b.SignatureAlgorithm {
		case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		default:
			return true
		}
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		switch b.SignatureAlgorithm {
		case x509.SHA384WithRSA, x509.ECDSAWithSHA384,
			x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		default:
			return true
		}
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		switch b.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.ECDSAWithSHA256,
			x509.SHA384WithRSA, x509.ECDSAWithSHA384,
			x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		default:
			return true
		}
	case x509.SHA1WithRSA:
	default:
		panic("not supported")
	}

	return false
}

func (s sortSKIs) Swap(i, j int) {
	s.skis[i], s.skis[j] = s.skis[j], s.skis[i]
}

type certLoader struct {
	sync.RWMutex
	skis      map[gokeyless.SKI]cert
	snis      map[string][]gokeyless.SKI
	serverIPs map[string][]gokeyless.SKI
}

func newCertLoader() *certLoader {
	return &certLoader{
		skis:      make(map[gokeyless.SKI]cert),
		snis:      make(map[string][]gokeyless.SKI),
		serverIPs: make(map[string][]gokeyless.SKI),
	}
}

var crtExt = regexp.MustCompile(`.+\.(crt|pem)`)

func (certs *certLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !crtExt.MatchString(info.Name()) {
			return nil
		}

		var in []byte
		if in, err = ioutil.ReadFile(path); err != nil {
			return err
		}

		var x509s []*x509.Certificate
		if x509s, err = helpers.ParseCertificatesPEM(in); err != nil {
			return err
		}

		if len(x509s) == 0 {
			return errors.New("invalid file")
		}

		ski, err := gokeyless.GetSKICert(x509s[0])
		if err != nil {
			return err
		}

		certs.Lock()
		certs.skis[ski] = cert{
			leaf: x509s[0],
			pem:  in,
		}

		if dnsname := x509s[0].Subject.CommonName; len(dnsname) != 0 {
			certs.snis[dnsname] = append(certs.snis[dnsname], ski)
			sort.Sort(sortSKIs{certs.snis[dnsname], certs.skis})
		}

		for _, dnsname := range x509s[0].DNSNames {
			certs.snis[dnsname] = append(certs.snis[dnsname], ski)
			sort.Sort(sortSKIs{certs.snis[dnsname], certs.skis})
		}

		for _, ip := range x509s[0].IPAddresses {
			certs.serverIPs[string(ip)] = append(certs.serverIPs[string(ip)], ski)
			sort.Sort(sortSKIs{certs.serverIPs[string(ip)], certs.skis})
		}

		certs.Unlock()
		return nil
	})
}

const (
	// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
	sslHashSHA1   = 2
	sslHashSHA256 = 4
	sslHashSHA384 = 5
	sslHashSHA512 = 6
	// Reserved code points
	sslHashCipher   = 224
	sslHashECCurves = 225

	// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
	sslSignatureRSA   = 1
	sslSignatureECDSA = 3
)

func (certs *certLoader) CertLoader(sigAlgs gokeyless.SigAlgs, serverIP net.IP, sni string) (certChain []byte, err error) {
	if len(sigAlgs) == 0 || (len(sni) == 0 && serverIP == nil) {
		return nil, gokeyless.ErrCertNotFound
	}

	var hasECDSA, hasSHA1RSA,
		hasSHA256RSA, hasSHA256ECDSA,
		hasSHA384RSA, hasSHA384ECDSA,
		hasSHA512RSA, hasSHA512ECDSA,
		hasSECP256R1, hasSECP384R1, hasSECP521R1 bool

	for i := 0; i < len(sigAlgs); i += 2 {
		hash := sigAlgs[i+0]
		sign := sigAlgs[i+1]

		switch (uint16(sign) << 8) | uint16(hash) {
		case (sslSignatureRSA << 8) | sslHashSHA1:
			hasSHA1RSA = true
		case (sslSignatureRSA << 8) | sslHashSHA256:
			hasSHA256RSA = true
		case (sslSignatureRSA << 8) | sslHashSHA384:
			hasSHA384RSA = true
		case (sslSignatureRSA << 8) | sslHashSHA512:
			hasSHA512RSA = true
		case (sslSignatureECDSA << 8) | sslHashSHA256:
			hasSHA256ECDSA = true
		case (sslSignatureECDSA << 8) | sslHashSHA384:
			hasSHA384ECDSA = true
		case (sslSignatureECDSA << 8) | sslHashSHA512:
			hasSHA512ECDSA = true
		case (sslSignatureECDSA << 8) | sslHashCipher:
			hasECDSA = true
		case (uint16(tls.CurveP256) << 8) | sslHashECCurves:
			hasSECP256R1 = true
		case (uint16(tls.CurveP384) << 8) | sslHashECCurves:
			hasSECP384R1 = true
		case (uint16(tls.CurveP521) << 8) | sslHashECCurves:
			hasSECP521R1 = true
		}
	}

	if !hasECDSA && !hasSHA1RSA &&
		!hasSHA256RSA && !hasSHA256ECDSA &&
		!hasSHA384RSA && !hasSHA384ECDSA &&
		!hasSHA512RSA && !hasSHA512ECDSA &&
		!hasSECP256R1 && !hasSECP384R1 && !hasSECP521R1 {
		return nil, gokeyless.ErrCertNotFound
	}

	certs.RLock()

	skis, ok := certs.snis[sni]
	if !ok {
		skis = certs.serverIPs[string(serverIP)]
	}

	err = gokeyless.ErrCertNotFound

	for _, ski := range skis {
		cert := certs.skis[ski]

		sigAlg := cert.leaf.SignatureAlgorithm
		pub, ok := cert.leaf.PublicKey.(*ecdsa.PublicKey)
		if !((sigAlg == x509.SHA1WithRSA && !hasSHA1RSA) ||
			(sigAlg == x509.SHA256WithRSA && !hasSHA256RSA) ||
			(sigAlg == x509.SHA384WithRSA && !hasSHA384RSA) ||
			(sigAlg == x509.SHA512WithRSA && !hasSHA512RSA) ||
			(sigAlg == x509.ECDSAWithSHA512 && (!hasSHA256ECDSA || !hasECDSA)) ||
			(sigAlg == x509.ECDSAWithSHA384 && (!hasSHA384ECDSA || !hasECDSA)) ||
			(sigAlg == x509.ECDSAWithSHA256 && (!hasSHA512ECDSA || !hasECDSA)) ||
			(ok && pub.Curve == elliptic.P256() && !hasSECP256R1) ||
			(ok && pub.Curve == elliptic.P384() && !hasSECP384R1) ||
			(ok && pub.Curve == elliptic.P521() && !hasSECP521R1)) {
			certChain, err = cert.pem, nil
			break
		}
	}

	certs.RUnlock()
	return
}
