// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

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
	"errors"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"

	"github.com/tmthrgd/keyless-tlv"
)

var (
	oidTLSFeature          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

type Client struct {
	sync.RWMutex
	keys map[keyless.SKI]crypto.PrivateKey
	snis map[string]*keyless.Certificate

	once map[string]*sync.Once

	client *acme.Client

	GetContext func(sni []byte) (ctx context.Context)
	MustStaple bool
}

func NewClient(client *acme.Client) *Client {
	return &Client{
		keys: make(map[keyless.SKI]crypto.PrivateKey),
		snis: make(map[string]*keyless.Certificate),

		once: make(map[string]*sync.Once),

		client: client,

		GetContext: func([]byte) context.Context {
			return context.Background()
		},
	}
}

func (ac *Client) GetKey(ski keyless.SKI) (priv crypto.PrivateKey, err error) {
	ac.RLock()
	priv, ok := ac.keys[ski]
	ac.RUnlock()

	if !ok {
		err = keyless.ErrorKeyNotFound
	}

	return
}

func (ac *Client) GetCertificate(op *keyless.Operation) (cert *keyless.Certificate, err error) {
	if len(op.SNI) == 0 {
		err = keyless.ErrorCertNotFound
		return
	}

	ac.RLock()
	cert, ok := ac.snis[string(op.SNI)]
	ac.RUnlock()

	switch {
	case ok:
		return
	case bytes.HasSuffix(op.SNI, []byte(".acme.invalid")):
		err = keyless.ErrorCertNotFound
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
		err = keyless.ErrorInternal
	}

	return
}

func (ac *Client) requestCertificate(sni []byte) (cert *keyless.Certificate, err error) {
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

	if ac.MustStaple {
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

	ski, err := keyless.GetSKI(&priv.PublicKey)
	if err != nil {
		return
	}

	cert = &keyless.Certificate{SKI: ski}
	cert.SetPayloadFromDER(der)

	ac.Lock()
	ac.keys[ski] = priv
	ac.snis[string(sni)] = cert

	delete(ac.once, string(sni))
	ac.Unlock()
	return
}

func (ac *Client) verify(ctx context.Context, sni []byte) error {
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

	ski, err := keyless.GetSKI(priv.Public())
	if err != nil {
		return err
	}

	cert2 := &keyless.Certificate{SKI: ski}
	cert2.SetPayloadFromDER(cert.Certificate)

	ac.Lock()
	ac.keys[ski] = priv
	ac.snis[name] = cert2
	ac.Unlock()

	if _, err = ac.client.Accept(ctx, chal); err == nil {
		_, err = ac.client.WaitAuthorization(ctx, authz.URI)
	}

	ac.Lock()
	delete(ac.keys, ski)
	delete(ac.snis, name)
	ac.Unlock()
	return err
}
