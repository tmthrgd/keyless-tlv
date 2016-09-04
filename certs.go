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

type cert struct {
	ski     SKI
	payload []byte
}

type certMap struct {
	sha1RSA, sha256RSA, sha256ECDSA *cert
}

type certLoader struct {
	sync.RWMutex
	skis      map[SKI]*cert
	snis      map[string]certMap
	serverIPs map[string]certMap
}

func newCertLoader() *certLoader {
	return &certLoader{
		skis:      make(map[SKI]*cert),
		snis:      make(map[string]certMap),
		serverIPs: make(map[string]certMap),
	}
}

func addCertToMap(m map[string]certMap, key string, cert *cert, leaf *x509.Certificate) {
	certs := m[key]

	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		certs.sha1RSA = cert
	case x509.SHA256WithRSA:
		certs.sha256RSA = cert
	case x509.ECDSAWithSHA256:
		certs.sha256ECDSA = cert
	}

	m[key] = certs
}

var crtExt = regexp.MustCompile(`.+\.(crt|pem)`)

func (c *certLoader) walker(path string, info os.FileInfo, err error) error {
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

	switch x509s[0].SignatureAlgorithm {
	case x509.SHA1WithRSA:
	case x509.SHA256WithRSA:
	case x509.ECDSAWithSHA256:
		if pub := x509s[0].PublicKey.(*ecdsa.PublicKey); pub.Curve != elliptic.P256() {
			return fmt.Errorf("unsupported elliptic curve '%s' for certificate signature algorithm '%s'",
				pub.Params().Name, x509s[0].SignatureAlgorithm)
		}
	default:
		return fmt.Errorf("unsupported certificate signature algorithm '%s'", x509s[0].SignatureAlgorithm)
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

	cert := &cert{
		ski:     ski,
		payload: b.Bytes(),
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

func (c *certLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, c.walker)
}

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

func (c *certLoader) GetCertificate(op Operation) (out []byte, outSKI SKI, err error) {
	if op.SKI.Valid() {
		c.RLock()

		if cert, ok := c.skis[op.SKI]; ok {
			out, outSKI = cert.payload, cert.ski
		} else {
			err = ErrorCertNotFound
		}

		c.RUnlock()
		return
	}

	if len(op.SNI) == 0 && op.ServerIP == nil {
		err = ErrorCertNotFound
		return
	}

	var hasSHA1RSA, hasSHA256RSA, hasSHA256ECDSA bool

	for i := 0; i < len(op.SigAlgs); i += 2 {
		switch binary.BigEndian.Uint16(op.SigAlgs[i:]) {
		case sslRSASHA1:
			hasSHA1RSA = true
		case sslRSASHA256:
			hasSHA256RSA = true
		case sslECDSASHA256:
			hasSHA256ECDSA = true
		}

		if hasSHA1RSA && hasSHA256RSA && hasSHA256ECDSA {
			break
		}
	}

	hasSHA256ECDSA = hasSHA256ECDSA && op.HasECDSACipher

	c.RLock()

	certs, ok := c.snis[string(op.SNI)]
	if !ok {
		certs, ok = c.serverIPs[string(op.ServerIP)]
	}

	if !ok {
		err = ErrorCertNotFound
	} else if op.SigAlgs != nil {
		if cert := certs.sha256ECDSA; hasSHA256ECDSA && cert != nil {
			out, outSKI = cert.payload, cert.ski
		} else if cert := certs.sha256RSA; hasSHA256RSA && cert != nil {
			out, outSKI = cert.payload, cert.ski
		} else if cert := certs.sha1RSA; hasSHA1RSA && cert != nil {
			out, outSKI = cert.payload, cert.ski
		} else if cert := certs.sha256RSA; cert != nil {
			out, outSKI = cert.payload, cert.ski
		} else if cert := certs.sha256ECDSA; cert != nil {
			out, outSKI = cert.payload, cert.ski
		} else {
			err = ErrorCertNotFound
		}
	} else if cert := certs.sha256RSA; op.SNI != nil && cert != nil {
		out, outSKI = cert.payload, cert.ski
	} else if cert := certs.sha1RSA; cert != nil {
		out, outSKI = cert.payload, cert.ski
	} else if cert := certs.sha256RSA; cert != nil {
		out, outSKI = cert.payload, cert.ski
	} else if cert := certs.sha256ECDSA; cert != nil {
		out, outSKI = cert.payload, cert.ski
	} else {
		err = ErrorCertNotFound
	}

	c.RUnlock()
	return
}
