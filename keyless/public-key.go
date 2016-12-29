package main

import (
	"encoding/base64"

	"golang.org/x/crypto/ed25519"
)

func publicKeyString(k ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(k)
}
