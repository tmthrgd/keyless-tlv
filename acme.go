// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keyless

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
)

var (
	oidTLSFeature          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

type ACMEClient struct {
	sync.RWMutex
	keys  map[SKI]crypto.Signer
	certs map[SKI]*Certificate
	snis  map[string]*Certificate

	once map[string]*sync.Once

	client *acme.Client

	HostPolicy func(sni []byte) (ok bool)
	GetContext func(sni []byte) (ctx context.Context)
	MustStaple func(sni []byte) bool
}

func NewACMEClient(client *acme.Client) *ACMEClient {
	return &ACMEClient{
		keys:  make(map[SKI]crypto.Signer),
		certs: make(map[SKI]*Certificate),
		snis:  make(map[string]*Certificate),

		once: make(map[string]*sync.Once),

		client: client,

		GetContext: func([]byte) context.Context {
			return context.Background()
		},
		MustStaple: func([]byte) bool {
			return false
		},
	}
}

func (ac *ACMEClient) GetKey(ski SKI) (priv crypto.Signer, err error) {
	ac.RLock()
	priv, ok := ac.keys[ski]
	ac.RUnlock()

	if !ok {
		err = ErrorKeyNotFound
	}

	return
}

func (ac *ACMEClient) GetCertificate(op *Operation) (cert *Certificate, err error) {
	var ok bool

	if op.SKI.Valid() {
		ac.RLock()
		cert, ok = ac.certs[op.SKI]
		ac.RUnlock()

		if !ok {
			err = ErrorCertNotFound
		}

		return
	}

	if len(op.SNI) == 0 {
		err = ErrorCertNotFound
		return
	}

	ac.RLock()
	cert, ok = ac.snis[string(op.SNI)]
	ac.RUnlock()

	switch {
	case ok:
		return
	case bytes.HasSuffix(op.SNI, []byte(".acme.invalid")):
		err = ErrorCertNotFound
		return
	case ac.HostPolicy != nil && !ac.HostPolicy(op.SNI):
		err = ErrorCertNotFound
		return
	}

	ac.Lock()

	if cert, ok = ac.snis[string(op.SNI)]; ok {
		ac.Unlock()
		return
	}

	once, ok := ac.once[string(op.SNI)]
	if !ok {
		once = new(sync.Once)
		ac.once[string(op.SNI)] = once
	}

	ac.Unlock()

	once.Do(func() {
		cert, err = ac.requestCertificate(op.SNI)
	})
	if cert != nil || err != nil {
		return
	}

	ac.RLock()
	cert, ok = ac.snis[string(op.SNI)]
	ac.RUnlock()

	if !ok {
		err = ErrorInternal
	}

	return
}

func (ac *ACMEClient) requestCertificate(sni []byte) (cert *Certificate, err error) {
	ctx := ac.GetContext(sni)

	if err = ac.verify(ctx, sni); err != nil {
		return
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: string(sni),
		},
	}

	if ac.MustStaple(sni) {
		req.Extensions = append(req.Extensions, pkix.Extension{
			Id:    oidTLSFeature,
			Value: mustStapleFeatureValue,
		})
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		return
	}

	der, _, err := ac.client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return
	}

	ski, err := GetSKI(&priv.PublicKey)
	if err != nil {
		return
	}

	cert = ac.buildCert(ski, der)

	ac.Lock()
	ac.keys[ski] = priv
	ac.certs[ski] = cert
	ac.snis[string(sni)] = cert

	delete(ac.once, string(sni))
	ac.Unlock()
	return
}

func (ac *ACMEClient) verify(ctx context.Context, sni []byte) error {
	authz, err := ac.client.Authorize(ctx, string(sni))
	if err != nil {
		return err
	}

	if authz.Status == acme.StatusValid {
		return nil
	}

	var chal *acme.Challenge

challenges:
	for _, c := range authz.Challenges {
		switch c.Type {
		case "tls-sni-02":
			chal = c
			break challenges
		case "tls-sni-01":
			chal = c
		}
	}

	if chal == nil {
		return errors.New("no supported challenge type found")
	}

	var cert tls.Certificate
	var name string

	if chal.Type == "tls-sni-01" {
		cert, name, err = ac.client.TLSSNI01ChallengeCert(chal.Token)
	} else {
		cert, name, err = ac.client.TLSSNI02ChallengeCert(chal.Token)
	}

	if err != nil {
		return err
	}

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("invalid private key")
	}

	ski, err := GetSKI(priv.Public())
	if err != nil {
		return err
	}

	cert2 := ac.buildCert(ski, cert.Certificate)

	ac.Lock()
	ac.keys[ski] = priv
	ac.certs[ski] = cert2
	ac.snis[name] = cert2
	ac.Unlock()

	defer func() {
		ac.Lock()
		delete(ac.keys, ski)
		delete(ac.certs, ski)
		delete(ac.snis, name)
		ac.Unlock()
	}()

	if _, err = ac.client.Accept(ctx, chal); err != nil {
		return err
	}

	_, err = ac.client.WaitAuthorization(ctx, authz.URI)
	return err
}

func (ac *ACMEClient) buildCert(ski SKI, ders [][]byte) *Certificate {
	var b bytes.Buffer

	for _, der := range ders {
		b.Grow(2 + len(der))

		binary.Write(&b, binary.BigEndian, uint16(len(der)))
		b.Write(der)
	}

	return &Certificate{
		Payload: b.Bytes(),
		SKI:     ski,
	}
}
