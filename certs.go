package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
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

func (certs *certLoader) walker(path string, info os.FileInfo, err error) error {
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
}

func (certs *certLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, certs.walker)
}

type gcTag byte

const (
	tagSignatureAlgorithms gcTag = iota + 1
	tagSupportedGroups
	tagECDSACipher
)

const (
	// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
	sslHashSHA1   = 2
	sslHashSHA256 = 4
	sslHashSHA384 = 5
	sslHashSHA512 = 6

	// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
	sslSignatureRSA   = 1
	sslSignatureECDSA = 3
)

func (certs *certLoader) GetCertificate(op *gokeyless.Operation) (certChain []byte, err error) {
	if len(op.Payload) == 0 || (len(op.SNI) == 0 && op.ServerIP == nil) {
		return nil, gokeyless.ErrCertNotFound
	}

	var hasECDSA, hasSHA1RSA,
		hasSHA256RSA, hasSHA256ECDSA,
		hasSHA384RSA, hasSHA384ECDSA,
		hasSHA512RSA, hasSHA512ECDSA,
		hasSECP256R1, hasSECP384R1, hasSECP521R1 bool

	var length int
	seen := make(map[gcTag]bool)

	for i := 0; i+2 < len(op.Payload); i += 3 + length {
		tag := gcTag(op.Payload[i])

		length = int(binary.BigEndian.Uint16(op.Payload[i+1 : i+3]))
		if i+3+length > len(op.Payload) {
			return nil, fmt.Errorf("%s length is %dB beyond end of body", tag, i+3+length-len(op.Payload))
		}

		data := op.Payload[i+3 : i+3+length]

		if seen[tag] {
			return nil, fmt.Errorf("tag %s seen multiple times", tag)
		}
		seen[tag] = true

		switch tag {
		case tagSignatureAlgorithms:
			if len(data)%2 != 0 {
				return nil, fmt.Errorf("invalid data for tagSignatureAlgorithms: %02x", data)
			}

			for j := 0; j < len(data); j += 2 {
				hash := data[j+0]
				sign := data[j+1]

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
				}
			}
		case tagSupportedGroups:
			if len(data)%2 != 0 {
				return nil, fmt.Errorf("invalid data for tagSupportedGroups: %02x", data)
			}

			for j := 0; j < len(data); j += 2 {
				switch tls.CurveID(binary.BigEndian.Uint16(data[j:])) {
				case tls.CurveP256:
					hasSECP256R1 = true
				case tls.CurveP384:
					hasSECP384R1 = true
				case tls.CurveP521:
					hasSECP521R1 = true
				}
			}
		case tagECDSACipher:
			if len(data) != 1 {
				return nil, fmt.Errorf("invalid data for tagECDSACipher: %02x", data)
			}

			hasECDSA = data[0] != 0
		default:
			return nil, fmt.Errorf("unknown tag: %s", tag)
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

	skis, ok := certs.snis[op.SNI]
	if !ok {
		skis = certs.serverIPs[string(op.ServerIP)]
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
