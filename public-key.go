package main

import (
	"encoding/base64"
	"golang.org/x/crypto/ed25519"
)

type publicKey ed25519.PublicKey

func (k publicKey) String() string {
	return base64.RawStdEncoding.EncodeToString(k)
}
