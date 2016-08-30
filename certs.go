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
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
)

//go:generate stringer -type=gcTag -output=certs_string.go

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

	validCurve := true
	pub, _ := x509s[0].PublicKey.(*ecdsa.PublicKey)
	switch x509s[0].SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
	case x509.ECDSAWithSHA256:
		validCurve = pub.Curve == elliptic.P256()
	case x509.ECDSAWithSHA384:
		validCurve = pub.Curve == elliptic.P384()
	case x509.ECDSAWithSHA512:
		validCurve = pub.Curve == elliptic.P521()
	default:
		return errors.New("unsupported certificate signature algorithm")
	}

	if !validCurve {
		return fmt.Errorf("unsupported elliptic curve '%s' for certificate signature algorithm '%s'",
			pub.Params().Name, x509s[0].SignatureAlgorithm)
	}

	ski, err := GetSKI(x509s[0].PublicKey)
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
	// Signature Algorithms for TLS 1.3 (See draft-ietf-tls-tls13-latest, section 4.2.2)
	sslRSASHA1   = 0x0201
	sslRSASHA256 = 0x0401
	sslRSASHA384 = 0x0501
	sslRSASHA512 = 0x0601

	sslECDSASHA256 = 0x0403
	sslECDSASHA384 = 0x0503
	sslECDSASHA512 = 0x0603

	sslRSAPSSSHA256 = 0x0700
	sslRSAPSSSHA384 = 0x0701
	sslRSAPSSSHA512 = 0x0702

	sslED25519 = 0x0703
	sslED448   = 0x0704
)

func (certs *certLoader) GetCertificate(op Operation) (out []byte, outSKI SKI, err error) {
	if op.SKI.Valid() {
		certs.RLock()

		if cert, ok := certs.skis[op.SKI]; ok {
			out, outSKI = cert.payload, op.SKI
		} else {
			err = ErrorCertNotFound
		}

		certs.RUnlock()
		return
	}

	if len(op.Payload) == 0 || (len(op.SNI) == 0 && op.ServerIP == nil) {
		err = ErrorCertNotFound
		return
	}

	var hasECDSA, hasSHA1RSA,
		hasSHA256RSA, hasSHA256ECDSA,
		hasSHA384RSA, hasSHA384ECDSA,
		hasSHA512RSA, hasSHA512ECDSA,
		hasSECP256R1, hasSECP384R1, hasSECP521R1 bool

	r := bytes.NewReader(op.Payload)

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
			err = WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", gcTag(tag), int(length)-r.Len())}
			return
		}

		if _, saw := seen[gcTag(tag)]; saw {
			err = WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", gcTag(tag))}
			return
		}
		seen[gcTag(tag)] = struct{}{}

		switch gcTag(tag) {
		case tagSignatureAlgorithms:
			if length%2 != 0 {
				err = WrappedError{ErrorFormat, fmt.Errorf("%s should be even number of bytes, was %d bytes", tagSignatureAlgorithms, length)}
				return
			}

			for j := 0; j < int(length); j += 2 {
				var scheme uint16
				binary.Read(r, binary.BigEndian, &scheme)

				switch scheme {
				case sslRSASHA1:
					hasSHA1RSA = true
				case sslRSASHA256:
					hasSHA256RSA = true
				case sslRSASHA384:
					hasSHA384RSA = true
				case sslRSASHA512:
					hasSHA512RSA = true
				case sslECDSASHA256:
					hasSHA256ECDSA = true
				case sslECDSASHA384:
					hasSHA384ECDSA = true
				case sslECDSASHA512:
					hasSHA512ECDSA = true
				}
			}
		case tagSupportedGroups:
			if length%2 != 0 {
				err = WrappedError{ErrorFormat, fmt.Errorf("%s should be even number of bytes, was %d bytes", tagSupportedGroups, length)}
				return
			}

			for j := 0; j < int(length); j += 2 {
				var curve uint16
				binary.Read(r, binary.BigEndian, &curve)

				switch tls.CurveID(curve) {
				case tls.CurveP256:
					hasSECP256R1 = true
				case tls.CurveP384:
					hasSECP384R1 = true
				case tls.CurveP521:
					hasSECP521R1 = true
				}
			}
		case tagECDSACipher:
			if length != 1 {
				err = WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 byte, was %d bytes", tagECDSACipher, length)}
				return
			}

			data, _ := r.ReadByte()
			hasECDSA = data != 0
		default:
			err = WrappedError{ErrorFormat, fmt.Errorf("unknown tag: %s", gcTag(tag))}
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

	skis, ok := certs.snis[string(op.SNI)]
	if !ok {
		skis = certs.serverIPs[string(op.ServerIP)]
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
