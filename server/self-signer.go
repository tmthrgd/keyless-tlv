package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"

	"github.com/tmthrgd/keyless"
)

var serialNumberMax = new(big.Int).Lsh(big.NewInt(1), 128)

type SelfSigner struct {
	sync.RWMutex
	keys  map[keyless.SKI]crypto.PrivateKey
	certs map[keyless.SKI]*keyless.Certificate
	snis  map[string]*keyless.Certificate

	once map[string]*sync.Once
}

func NewSelfSigner() *SelfSigner {
	return &SelfSigner{
		keys:  make(map[keyless.SKI]crypto.PrivateKey),
		certs: make(map[keyless.SKI]*keyless.Certificate),
		snis:  make(map[string]*keyless.Certificate),

		once: make(map[string]*sync.Once),
	}
}

func (ss *SelfSigner) GetKey(ski keyless.SKI) (priv crypto.PrivateKey, err error) {
	ss.RLock()
	priv, ok := ss.keys[ski]
	ss.RUnlock()

	if !ok {
		err = keyless.ErrorKeyNotFound
	}

	return
}

func (ss *SelfSigner) GetCertificate(op *keyless.Operation) (cert *keyless.Certificate, err error) {
	var ok bool

	if op.SKI.Valid() {
		ss.RLock()
		cert, ok = ss.certs[op.SKI]
		ss.RUnlock()

		if !ok {
			err = keyless.ErrorCertNotFound
		}

		return
	}

	if len(op.SNI) == 0 {
		err = keyless.ErrorCertNotFound
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
		cert, err = ss.generateCertificate(op.SNI)
	})
	if cert != nil || err != nil {
		return
	}

	ss.RLock()
	cert, ok = ss.snis[string(op.SNI)]
	ss.RUnlock()

	if !ok {
		err = keyless.ErrorInternal
	}

	return
}

func (ss *SelfSigner) generateCertificate(sni []byte) (cert *keyless.Certificate, err error) {
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
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	ski, err := keyless.GetSKI(&priv.PublicKey)
	if err != nil {
		return
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	cert = &keyless.Certificate{SKI: ski}
	cert.SetPayloadFromDER([][]byte{der})

	ss.Lock()
	ss.keys[ski] = priv
	ss.certs[ski] = cert
	ss.snis[string(sni)] = cert

	delete(ss.once, string(sni))
	ss.Unlock()
	return
}
