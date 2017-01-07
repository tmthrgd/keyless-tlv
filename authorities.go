package keyless

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/ed25519"
)

type authCacheKey struct {
	Authorisation [8 + ed25519.SignatureSize]byte
	PublicKey     [ed25519.PublicKeySize]byte
}

type Authorities struct {
	sync.RWMutex
	m map[string]ed25519.PublicKey

	cache map[authCacheKey]bool
}

func NewAuthorities() *Authorities {
	return &Authorities{
		m:     make(map[string]ed25519.PublicKey),
		cache: make(map[authCacheKey]bool),
	}
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
		return WrappedError{ErrorNotAuthorised,
			errors.New("request does not have a signature")}
	}

	if len(op.Authorisation) != 8+ed25519.SignatureSize {
		return WrappedError{ErrorNotAuthorised,
			fmt.Errorf("%s should be %d bytes, was %d bytes", TagAuthorisation,
				8+ed25519.SignatureSize, len(op.Authorisation))}
	}

	var cacheKey authCacheKey
	copy(cacheKey.Authorisation[:], op.Authorisation)
	copy(cacheKey.PublicKey[:], pub)

	a.RLock()
	key, hasKey := a.m[string(op.Authorisation[:8])]
	ok, inCache := a.cache[cacheKey]
	a.RUnlock()

	if !hasKey {
		return ErrorNotAuthorised
	}

	if !inCache {
		ok = ed25519.Verify(key, pub, op.Authorisation[8:])

		const (
			maxCacheSize = 1024
			drainCacheTo = 768
		)

		a.Lock()

		if i := len(a.cache); i > maxCacheSize {
			for k := range a.cache {
				delete(a.cache, k)

				if i--; i <= drainCacheTo {
					break
				}
			}
		}

		a.cache[cacheKey] = ok
		a.Unlock()
	}

	if ok {
		return nil
	}

	return ErrorNotAuthorised
}

func (a *Authorities) ReadFrom(path string) error {
	a.Lock()
	a.m = make(map[string]ed25519.PublicKey)
	a.cache = make(map[authCacheKey]bool)
	a.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	defer f.Close()

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
