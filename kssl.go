package keyless

import (
	"crypto"
	"encoding/base64"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

type GetCertFunc func(op *Operation) (cert *Certificate, err error)
type GetKeyFunc func(ski SKI) (priv crypto.PrivateKey, err error)
type IsAuthorisedFunc func(pub ed25519.PublicKey, op *Operation) error

const (
	VersionMajor = 2
	VersionMinor = 0
)

type RequestHandler struct {
	GetCert GetCertFunc
	GetKey  GetKeyFunc

	sync.RWMutex
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	Authorisation []byte

	IsAuthorised IsAuthorisedFunc

	NoSignature bool
	SkipPadding bool
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	hdr := Header{NoSignature: h.NoSignature}

	body, err := hdr.Unmarshal(in)
	if err != nil {
		return
	}

	op := new(Operation)

	switch {
	case hdr.Major != VersionMajor:
		err = ErrorVersionMismatch
	case int(hdr.Length) != len(body):
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	case !h.NoSignature && !ed25519.Verify(hdr.PublicKey, body, hdr.Signature):
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
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
		op.Opcode = OpResponse
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

	log.Printf("id: %d, elapsed: %s, request: %dB, response: %dB", hdr.ID, time.Since(start), len(in), len(out))
	return
}
