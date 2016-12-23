package main

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ed25519"
)

func (h *RequestHandler) ReadKeyFile(path string) error {
	keyfile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	const expectedSize = ed25519.PrivateKeySize + 8 + ed25519.SignatureSize
	if len(keyfile) != expectedSize {
		return fmt.Errorf("invalid key file: expected length %d, got length %d", expectedSize, len(keyfile))
	}

	h.Lock()

	h.PrivateKey = keyfile[:ed25519.PrivateKeySize]
	h.PublicKey = PublicKey(h.PrivateKey.Public().(ed25519.PublicKey))

	h.Authority.ID = keyfile[ed25519.PrivateKeySize : ed25519.PrivateKeySize+8]
	h.Authority.Signature = keyfile[ed25519.PrivateKeySize+8:]

	h.Unlock()
	return nil
}