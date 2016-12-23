package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/ed25519"
)

type Authorities struct {
	sync.RWMutex
	m map[string]ed25519.PublicKey
}

func (a *Authorities) Add(publicKey ed25519.PublicKey) {
	id := sha256.Sum256(publicKey)

	a.Lock()
	a.m[string(id[:8])] = publicKey
	a.Unlock()
}

func (a *Authorities) Remove(publicKey ed25519.PublicKey) {
	id := sha256.Sum256(publicKey)

	a.Lock()
	delete(a.m, string(id[:8]))
	a.Unlock()
}

func (a *Authorities) IsAuthorised(pub ed25519.PublicKey, op *Operation) error {
	if len(pub) == 0 {
		panic("request does not have a signature")
	}

	if len(op.Authorisation) != 8+ed25519.SignatureSize {
		return WrappedError{ErrorFormat, fmt.Errorf("%s should be %d bytes, was %d bytes",
			TagAuthorisation, 8+ed25519.SignatureSize, len(op.Authorisation))}
	}

	a.RLock()
	key, ok := a.m[string(op.Authorisation[:8])]
	a.RUnlock()

	if !ok || !ed25519.Verify(key, pub, op.Authorisation[8:]) {
		return WrappedError{
			Code: ErrorNotAuthorised,
			Err:  fmt.Errorf("%s not authorised", PublicKey(pub)),
		}
	}

	return nil
}

func (a *Authorities) ReadFrom(path string) error {
	a.Lock()
	a.m = make(map[string]ed25519.PublicKey)
	a.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	var dst [ed25519.PublicKeySize]byte

	s := bufio.NewScanner(f)

	for s.Scan() {
		if _, err := base64.RawStdEncoding.Decode(dst[:], s.Bytes()); err != nil {
			return err
		}

		a.Add(dst[:])
	}

	return s.Err()
}
