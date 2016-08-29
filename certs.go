package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
)

type cert struct {
	leaf    *x509.Certificate
	payload []byte
}

type sortSKIs struct {
	skis []SKI
	cert map[SKI]cert
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
	skis      map[SKI]cert
	snis      map[string][]SKI
	serverIPs map[string][]SKI
}

func newCertLoader() *certLoader {
	return &certLoader{
		skis:      make(map[SKI]cert),
		snis:      make(map[string][]SKI),
		serverIPs: make(map[string][]SKI),
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

	in, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	x509s, err := helpers.ParseCertificatesPEM(in)
	if err != nil {
		return err
	}

	if len(x509s) == 0 {
		return errors.New("invalid file")
	}

	ski, err := GetSKIForCert(x509s[0])
	if err != nil {
		return err
	}

	var b bytes.Buffer

	for _, x509 := range x509s {
		binary.Write(&b, binary.BigEndian, uint16(len(x509.Raw)))
		b.Write(x509.Raw)
	}

	certs.Lock()
	certs.skis[ski] = cert{
		leaf:    x509s[0],
		payload: b.Bytes(),
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

func (certs *certLoader) GetCertificate(ski SKI, sni []byte, serverIP net.IP, payload []byte) (out []byte, outSKI SKI, err error) {
	if ski.Valid() {
		certs.RLock()

		if cert, ok := certs.skis[ski]; ok {
			out, outSKI = cert.payload, ski
		} else {
			err = ErrorCertNotFound
		}

		certs.RUnlock()
		return
	}

	if len(payload) == 0 || (len(sni) == 0 && serverIP == nil) {
		err = ErrorCertNotFound
		return
	}

	var hasECDSA, hasSHA1RSA,
		hasSHA256RSA, hasSHA256ECDSA,
		hasSHA384RSA, hasSHA384ECDSA,
		hasSHA512RSA, hasSHA512ECDSA,
		hasSECP256R1, hasSECP384R1, hasSECP521R1 bool

	r := bytes.NewReader(payload)

	seen := make(map[gcTag]struct{})

	for r.Len() != 0 {
		var tag byte
		if tag, err = r.ReadByte(); err != nil {
			err = WrappedError{ErrorFormat, err}
			return
		}

		var length uint16
		if err = binary.Read(r, binary.BigEndian, &length); err != nil {
			err = WrappedError{ErrorFormat, err}
			return
		}

		if int(length) > r.Len() {
			err = WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", tag, int(length)-r.Len())}
			return
		}

		if _, saw := seen[gcTag(tag)]; saw {
			err = WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", tag)}
			return
		}
		seen[gcTag(tag)] = struct{}{}

		var offset int64
		if offset, err = r.Seek(int64(length), io.SeekCurrent); err != nil {
			err = WrappedError{ErrorInternal, err}
			return
		}

		data := payload[offset-int64(length) : offset]

		switch gcTag(tag) {
		case tagSignatureAlgorithms:
			if len(data)%2 != 0 {
				err = WrappedError{ErrorFormat, fmt.Errorf("invalid data for tagSignatureAlgorithms: %02x", data)}
				return
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
				err = WrappedError{ErrorFormat, fmt.Errorf("invalid data for tagSupportedGroups: %02x", data)}
				return
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
				err = WrappedError{ErrorFormat, fmt.Errorf("invalid data for tagECDSACipher: %02x", data)}
				return
			}

			hasECDSA = data[0] != 0
		default:
			err = WrappedError{ErrorFormat, fmt.Errorf("unknown tag: %s", tag)}
			return
		}
	}

	err = ErrorCertNotFound

	if !hasECDSA && !hasSHA1RSA &&
		!hasSHA256RSA && !hasSHA256ECDSA &&
		!hasSHA384RSA && !hasSHA384ECDSA &&
		!hasSHA512RSA && !hasSHA512ECDSA &&
		!hasSECP256R1 && !hasSECP384R1 && !hasSECP521R1 {
		return
	}

	certs.RLock()

	skis, ok := certs.snis[string(sni)]
	if !ok {
		skis = certs.serverIPs[string(serverIP)]
	}

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
			out, outSKI, err = cert.payload, ski, nil
			break
		}
	}

	certs.RUnlock()
	return
}
