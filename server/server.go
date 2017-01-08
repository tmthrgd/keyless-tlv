package server

import (
	"crypto"
	"encoding/base64"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/tmthrgd/keyless"
)

type GetCertFunc func(op *keyless.Operation) (cert *keyless.Certificate, err error)
type GetKeyFunc func(ski keyless.SKI) (priv crypto.PrivateKey, err error)

type RequestHandler struct {
	GetCert GetCertFunc
	GetKey  GetKeyFunc

	sync.RWMutex
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	Authorisation []byte

	IsAuthorised keyless.IsAuthorisedFunc

	NoSignature bool
	SkipPadding bool
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	hdr := keyless.Header{NoSignature: h.NoSignature}

	body, err := hdr.Unmarshal(in)
	if err != nil {
		return
	}

	op := new(keyless.Operation)

	switch {
	case hdr.Major != keyless.VersionMajor:
		err = keyless.ErrorVersionMismatch
	case int(hdr.Length) != len(body):
		err = keyless.WrappedError{keyless.ErrorFormat,
			errors.New("invalid header length")}
	case !h.NoSignature && !ed25519.Verify(hdr.PublicKey, body, hdr.Signature):
		err = keyless.WrappedError{keyless.ErrorNotAuthorised,
			errors.New("invalid signature")}
	default:
		err = op.Unmarshal(body)
	}

	if err == nil {
		if h.NoSignature {
			log.Printf("id: %d, %v", hdr.ID, op)
		} else {
			log.Printf("id: %d, key: %s, %v", hdr.ID,
				base64.RawStdEncoding.EncodeToString(hdr.PublicKey), op)
		}

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(hdr.PublicKey, op)
		}

		if err == nil {
			op, err = h.Process(op)
		}
	}

	if err != nil {
		log.Printf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	if op.Opcode == 0 {
		op.Opcode = keyless.OpResponse
	}

	op.SkipPadding = h.SkipPadding

	var privKey ed25519.PrivateKey

	if !h.NoSignature {
		h.RLock()
		hdr.PublicKey, privKey = h.PublicKey, h.PrivateKey
		op.Authorisation = h.Authorisation
		h.RUnlock()
	}

	out = hdr.Marshal(op, privKey, in[:0])

	log.Printf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID, time.Since(start), len(in), len(out))
	return
}
