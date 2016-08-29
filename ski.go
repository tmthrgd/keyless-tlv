// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

type SKI [sha1.Size]byte

var nilSKI SKI

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

func GetSKI(pub crypto.PublicKey) (ski SKI, err error) {
	var publicKeyBytes []byte

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if publicKeyBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		}); err != nil {
			return
		}
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		err = errors.New("only RSA and ECDSA public keys supported")
		return
	}

	ski = sha1.Sum(publicKeyBytes)
	return
}

func GetSKIForCert(cert *x509.Certificate) (SKI, error) {
	return GetSKI(cert.PublicKey)
}

func (ski SKI) Valid() bool {
	return !bytes.Equal(ski[:], nilSKI[:])
}
