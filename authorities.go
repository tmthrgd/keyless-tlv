package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
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

func (a *Authorities) Get(id []byte) (ed25519.PublicKey, bool) {
	a.RLock()
	key, ok := a.m[string(id)]
	a.RUnlock()

	return key, ok
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
