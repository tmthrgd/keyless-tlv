package main

import (
	"encoding/base64"

	"golang.org/x/crypto/ed25519"
)

type PublicKey ed25519.PublicKey

func (k PublicKey) String() string {
	return base64.RawStdEncoding.EncodeToString(k)
}
