package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/ed25519"
)

type SKI [sha1.Size]byte

var nilSKI SKI

func GetSKI(pub crypto.PublicKey) (ski SKI, err error) {
	var publicKeyBytes []byte

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if publicKeyBytes, err = asn1.Marshal(*pub); err != nil {
			return
		}
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	case ed25519.PublicKey:
		publicKeyBytes = pub
	default:
		err = errors.New("unsupported public key type")
		return
	}

	ski = sha1.Sum(publicKeyBytes)
	return
}

func (ski SKI) String() string {
	if ski == nilSKI {
		return "<nil>"
	}

	return hex.EncodeToString(ski[:])
}

func (ski SKI) Valid() bool {
	return ski != nilSKI
}
