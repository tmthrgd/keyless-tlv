package keyless

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

	const expectedSize = ed25519.PrivateKeySize + authSize
	if len(keyfile) != expectedSize {
		return fmt.Errorf("invalid key file: expected length %d, got length %d", expectedSize, len(keyfile))
	}

	h.Lock()
	h.PrivateKey = keyfile[:ed25519.PrivateKeySize:ed25519.PrivateKeySize]
	h.PublicKey = h.PrivateKey.Public().(ed25519.PublicKey)
	h.Authorisation = keyfile[ed25519.PrivateKeySize:]
	h.Unlock()
	return nil
}
