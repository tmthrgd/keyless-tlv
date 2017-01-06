package keyless

import (
	"bytes"
	"crypto"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/dustin/go-humanize"
)

type Certificate struct {
	Payload []byte
	SKI     SKI
	OCSP    []byte
}

type GetCertFunc func(op *Operation) (cert *Certificate, err error)
type GetKeyFunc func(ski SKI) (priv crypto.Signer, err error)
type IsAuthorisedFunc func(pub ed25519.PublicKey, op *Operation) error

const (
	VersionMajor = 2
	VersionMinor = 0

	HeaderLength            = 8 + ed25519.PublicKeySize + ed25519.SignatureSize
	HeaderLengthNoSignature = 8
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
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	r := bytes.NewReader(in)

	hdr := Header{NoSignature: h.NoSignature}

	hdrLen, err := hdr.Unmarshal(r)
	if err != nil {
		return
	}

	op := new(Operation)

	switch {
	case hdr.Major != VersionMajor:
		err = ErrorVersionMismatch
	case int(hdr.Length) != r.Len():
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	case !h.NoSignature && !ed25519.Verify(hdr.PublicKey, in[hdrLen:], hdr.Signature):
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
	default:
		err = op.Unmarshal(in[hdrLen:])
	}

	if err == nil {
		if h.NoSignature {
			log.Printf("id: %d, %v", hdr.ID, op)
		} else {
			log.Printf("id: %d, key: %s, %v", hdr.ID, publicKeyString(hdr.PublicKey), op)
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

	var privKey ed25519.PrivateKey

	if !h.NoSignature {
		h.RLock()
		hdr.PublicKey, privKey = h.PublicKey, h.PrivateKey
		op.Authorisation = h.Authorisation
		h.RUnlock()
	}

	out = hdr.Marshal(op, privKey, in[:0])

	log.Printf("id: %d, elapsed: %s, request: %s, response: %s", hdr.ID, time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}
