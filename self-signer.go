package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"sync"
	"time"
)

var serialNumberMax = new(big.Int).Lsh(big.NewInt(1), 128)

type SelfSigner struct {
	sync.RWMutex
	keys  map[SKI]crypto.Signer
	certs map[SKI]*Certificate
	snis  map[string]*Certificate

	once map[string]*sync.Once
}

func NewSelfSigner() *SelfSigner {
	return &SelfSigner{
		keys:  make(map[SKI]crypto.Signer),
		certs: make(map[SKI]*Certificate),
		snis:  make(map[string]*Certificate),

		once: make(map[string]*sync.Once),
	}
}

func (ss *SelfSigner) GetKey(ski SKI) (priv crypto.Signer, err error) {
	ss.RLock()
	priv, ok := ss.keys[ski]
	ss.RUnlock()

	if !ok {
		err = ErrorKeyNotFound
	}

	return
}

func (ss *SelfSigner) GetCertificate(op *Operation) (cert *Certificate, err error) {
	var ok bool

	if op.SKI.Valid() {
		ss.RLock()
		cert, ok = ss.certs[op.SKI]
		ss.RUnlock()

		if !ok {
			err = ErrorCertNotFound
		}

		return
	}

	if len(op.SNI) == 0 {
		err = ErrorCertNotFound
		return
	}

	ss.RLock()
	cert, ok = ss.snis[string(op.SNI)]
	ss.RUnlock()

	if ok {
		return
	}

	ss.Lock()

	if cert, ok = ss.snis[string(op.SNI)]; ok {
		ss.Unlock()
		return
	}

	once, ok := ss.once[string(op.SNI)]
	if !ok {
		once = new(sync.Once)
		ss.once[string(op.SNI)] = once
	}

	ss.Unlock()

	once.Do(func() {
		err = ss.generateCertificate(op.SNI)
	})
	if err != nil {
		return
	}

	ss.RLock()
	cert, ok = ss.snis[string(op.SNI)]
	ss.RUnlock()

	if !ok {
		err = ErrorInternal
	}

	return
}

func (ss *SelfSigner) generateCertificate(sni []byte) (err error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberMax)
	if err != nil {
		return
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(10, 0, 0).UTC()

	template := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,

		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName:   string(sni),
			Organization: []string{"keyless self-signed"},
		},

		NotBefore: time.Date(notBefore.Year(), notBefore.Month(), notBefore.Day(), 0, 0, 0, 0, notBefore.Location()),
		NotAfter:  time.Date(notAfter.Year(), notAfter.Month(), notAfter.Day(), 23, 59, 59, 0, notAfter.Location()),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		DNSNames: []string{string(sni)},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	ski, err := GetSKI(&priv.PublicKey)
	if err != nil {
		return
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	cert := &Certificate{
		Payload: make([]byte, 2+len(der)),
		SKI:     ski,
	}
	binary.BigEndian.PutUint16(cert.Payload, uint16(len(der)))
	copy(cert.Payload[2:], der)

	ss.Lock()
	ss.keys[ski] = priv
	ss.certs[ski] = cert
	ss.snis[string(sni)] = cert

	delete(ss.once, string(sni))
	ss.Unlock()
	return
}
