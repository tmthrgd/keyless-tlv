package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
)

type certMap struct {
	sha1RSA, sha256RSA, sha256ECDSA, sha384ECDSA *Certificate
}

type CertLoader struct {
	sync.RWMutex
	skis      map[SKI]*Certificate
	snis      map[string]certMap
	serverIPs map[string]certMap

	Fallback GetCertFunc
}

func NewCertLoader() *CertLoader {
	return &CertLoader{
		skis:      make(map[SKI]*Certificate),
		snis:      make(map[string]certMap),
		serverIPs: make(map[string]certMap),
	}
}

func addCertToMap(m map[string]certMap, key string, cert *Certificate, leaf *x509.Certificate) {
	certs := m[key]

	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		certs.sha1RSA = cert
	case x509.SHA256WithRSA:
		certs.sha256RSA = cert
	case x509.ECDSAWithSHA256:
		certs.sha256ECDSA = cert
	case x509.ECDSAWithSHA384:
		certs.sha384ECDSA = cert
	}

	m[key] = certs
}

var crtExt = regexp.MustCompile(`.+\.(crt|pem)`)

func (c *CertLoader) walker(path string, info os.FileInfo, err error) error {
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

	pub, _ := x509s[0].PublicKey.(*ecdsa.PublicKey)
	validCurve := true

	switch x509s[0].SignatureAlgorithm {
	case x509.SHA1WithRSA:
	case x509.SHA256WithRSA:
	case x509.ECDSAWithSHA256:
		validCurve = pub.Curve == elliptic.P256()
	case x509.ECDSAWithSHA384:
		validCurve = pub.Curve == elliptic.P384()
	default:
		return fmt.Errorf("unsupported certificate signature algorithm '%s'", x509s[0].SignatureAlgorithm)
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

	cert := &Certificate{
		Payload: b.Bytes(),
		SKI:     ski,
	}

	c.Lock()
	c.skis[ski] = cert

	if dnsname := x509s[0].Subject.CommonName; len(dnsname) != 0 {
		addCertToMap(c.snis, dnsname, cert, x509s[0])
	}

	for _, dnsname := range x509s[0].DNSNames {
		addCertToMap(c.snis, dnsname, cert, x509s[0])
	}

	for _, ip := range x509s[0].IPAddresses {
		addCertToMap(c.serverIPs, string(ip), cert, x509s[0])
	}

	c.Unlock()
	return nil
}

func (c *CertLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, c.walker)
}

const (
	// Signature Algorithms for TLS 1.3 (See draft-ietf-tls-tls13-latest, section 4.2.3)
	sslRSASHA1   = 0x0201
	sslRSASHA256 = 0x0401
	sslRSASHA384 = 0x0501
	sslRSASHA512 = 0x0601

	sslECDSASHA256 = 0x0403
	sslECDSASHA384 = 0x0503
	sslECDSASHA512 = 0x0603

	sslRSAPSSSHA256 = 0x0804
	sslRSAPSSSHA384 = 0x0805
	sslRSAPSSSHA512 = 0x0806

	sslED25519 = 0x0807
	sslED448   = 0x0808
)

func (c *CertLoader) GetCertificate(op *Operation) (cert *Certificate, err error) {
	var ok bool

	if op.SKI.Valid() {
		c.RLock()
		cert, ok = c.skis[op.SKI]
		c.RUnlock()

		switch {
		case ok:
		case c.Fallback != nil:
			cert, err = c.Fallback(op)
		default:
			err = ErrorCertNotFound
		}

		return
	}

	if len(op.SNI) == 0 && op.ServerIP == nil {
		if c.Fallback != nil {
			cert, err = c.Fallback(op)
		} else {
			err = ErrorCertNotFound
		}

		return
	}

	var hasSHA1RSA, hasSHA256RSA, hasSHA256ECDSA, hasSHA384ECDSA bool

	for i := 0; i < len(op.SigAlgs); i += 2 {
		switch binary.BigEndian.Uint16(op.SigAlgs[i:]) {
		case sslRSASHA1:
			hasSHA1RSA = true
		case sslRSASHA256:
			hasSHA256RSA = true
		case sslECDSASHA256:
			hasSHA256ECDSA = true
		case sslECDSASHA384:
			hasSHA384ECDSA = true
		}

		if hasSHA1RSA && hasSHA256RSA && hasSHA256ECDSA && hasSHA384ECDSA {
			break
		}
	}

	c.RLock()

	certs, ok := c.snis[string(op.SNI)]
	if !ok {
		certs, ok = c.serverIPs[string(op.ServerIP)]
	}

	if !ok {
		err = ErrorCertNotFound
	} else if op.SigAlgs != nil {
		switch {
		case hasSHA256ECDSA && op.HasECDSACipher && certs.sha256ECDSA != nil:
			cert = certs.sha256ECDSA
		case hasSHA384ECDSA && op.HasECDSACipher && certs.sha384ECDSA != nil:
			cert = certs.sha384ECDSA
		case hasSHA256RSA && certs.sha256RSA != nil:
			cert = certs.sha256RSA
		case hasSHA1RSA && certs.sha1RSA != nil:
			cert = certs.sha1RSA
		case certs.sha256RSA != nil:
			cert = certs.sha256RSA
		case certs.sha256ECDSA != nil:
			cert = certs.sha256ECDSA
		case certs.sha384ECDSA != nil:
			cert = certs.sha384ECDSA
		default:
			err = ErrorCertNotFound
		}
	} else {
		switch {
		case op.SNI != nil && certs.sha256RSA != nil:
			cert = certs.sha256RSA
		case certs.sha1RSA != nil:
			cert = certs.sha1RSA
		case certs.sha256RSA != nil:
			cert = certs.sha256RSA
		case certs.sha256ECDSA != nil:
			cert = certs.sha256ECDSA
		case certs.sha384ECDSA != nil:
			cert = certs.sha384ECDSA
		default:
			err = ErrorCertNotFound
		}
	}

	c.RUnlock()

	if err == ErrorCertNotFound && c.Fallback != nil {
		cert, err = c.Fallback(op)
	}

	return
}
