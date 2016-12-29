package keyless

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func BenchmarkIsAuthorised(b *testing.B) {
	authPub, authPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}

	id := sha256.Sum256(authPub)

	a := NewAuthorities()
	a.Add(authPub)

	var pub [ed25519.PublicKeySize]byte
	sig := ed25519.Sign(authPriv, pub[:])

	op := &Operation{
		Authorisation: bytes.Join([][]byte{
			id[:8],
			sig,
		}, nil),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := a.IsAuthorised(pub[:], op); err != nil {
			b.Fatal(err)
		}
	}
}
