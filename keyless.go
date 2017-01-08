package keyless

import "golang.org/x/crypto/ed25519"

const (
	VersionMajor = 2
	VersionMinor = 0
)

type IsAuthorisedFunc func(pub ed25519.PublicKey, op *Operation) error
