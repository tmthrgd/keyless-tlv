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

const (
	AuthIDSize = 8
	AuthSize   = AuthIDSize + ed25519.SignatureSize
)

type authCacheKey struct {
	Authorisation [AuthSize]byte
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
	a.m[string(id[:AuthIDSize])] = publicKey
	a.Unlock()
}

func (a *Authorities) Remove(publicKey ed25519.PublicKey) {
	id := sha256.Sum256(publicKey)

	a.Lock()
	delete(a.m, string(id[:AuthIDSize]))
	a.Unlock()
}

func (a *Authorities) IsAuthorised(pub ed25519.PublicKey, op *Operation) error {
	if len(pub) == 0 {
		return WrappedError{ErrorNotAuthorised,
			errors.New("request does not have a signature")}
	}

	if len(op.Authorisation) != AuthSize {
		return WrappedError{ErrorNotAuthorised,
			fmt.Errorf("%s should be %d bytes, was %d bytes", TagAuthorisation,
				AuthSize, len(op.Authorisation))}
	}

	var cacheKey authCacheKey
	copy(cacheKey.Authorisation[:], op.Authorisation)
	copy(cacheKey.PublicKey[:], pub)

	a.RLock()
	key, hasKey := a.m[string(op.Authorisation[:AuthIDSize])]
	ok, inCache := a.cache[cacheKey]
	a.RUnlock()

	if !hasKey {
		return ErrorNotAuthorised
	}

	if !inCache {
		ok = ed25519.Verify(key, pub, op.Authorisation[AuthIDSize:])

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

	dst := make([]byte, ed25519.PublicKeySize, ed25519.PublicKeySize*2)

	s := bufio.NewScanner(f)

	for s.Scan() {
		if base64.RawStdEncoding.DecodedLen(len(s.Bytes())) > cap(dst) {
			return errors.New("invalid key line")
		}

		n, err := base64.RawStdEncoding.Decode(dst[:cap(dst)], s.Bytes())
		if err != nil {
			return err
		}

		if n != ed25519.PublicKeySize {
			return fmt.Errorf("invalid key size, expected %d, got %d",
				ed25519.PublicKeySize, n)
		}

		a.Add(dst)
	}

	return s.Err()
}
