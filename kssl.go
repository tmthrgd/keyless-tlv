package main

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	humanize "github.com/dustin/go-humanize"
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

var nilSig [ed25519.SignatureSize]byte

type RequestHandler struct {
	GetCert GetCertFunc
	GetKey  GetKeyFunc

	sync.RWMutex
	PublicKey     PublicKey
	PrivateKey    ed25519.PrivateKey
	Authorisation []byte

	IsAuthorised IsAuthorisedFunc

	NoSignature bool
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	headerLength := HeaderLength
	if h.NoSignature {
		headerLength = HeaderLengthNoSignature
	}

	r := bytes.NewReader(in)

	var major byte
	if major, err = r.ReadByte(); err != nil {
		return
	}

	if _, err = r.ReadByte(); err != nil {
		return
	}

	var length uint16
	if err = binary.Read(r, binary.BigEndian, &length); err != nil {
		return
	}

	var id uint32
	if err = binary.Read(r, binary.BigEndian, &id); err != nil {
		return
	}

	var remPublic [ed25519.PublicKeySize]byte
	var remSig [ed25519.SignatureSize]byte

	if !h.NoSignature {
		if _, err = r.Read(remPublic[:]); err != nil {
			return
		}

		if _, err = r.Read(remSig[:]); err != nil {
			return
		}
	}

	op := new(Operation)

	if major != VersionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else if !h.NoSignature &&
		!ed25519.Verify(remPublic[:], in[headerLength:], remSig[:]) {
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
	} else if err = op.Unmarshal(in[headerLength:]); err == nil {
		if h.NoSignature {
			log.Printf("id: %d, %v", id, op)
		} else {
			log.Printf("id: %d, key: %s, %v", id, PublicKey(remPublic[:]), op)
		}

		if h.IsAuthorised != nil {
			if h.NoSignature {
				err = h.IsAuthorised(nil, op)
			} else {
				err = h.IsAuthorised(remPublic[:], op)
			}
		}

		if err == nil {
			op, err = h.Process(op)
		}
	}

	if err != nil {
		log.Printf("id: %d, %v", id, err)

		op.FromError(err)
	}

	if op.Opcode == 0 {
		op.Opcode = OpResponse
	}

	b := bytes.NewBuffer(in[:0])
	b.Grow(PadTo + 3)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	var privKey ed25519.PrivateKey

	if !h.NoSignature {
		h.RLock()

		b.Write(h.PublicKey)
		b.Write(nilSig[:]) // signature placeholder

		privKey = h.PrivateKey

		op.Authorisation = h.Authorisation

		h.RUnlock()
	}

	op.Marshal(b)

	out, err = b.Bytes(), nil
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-headerLength))

	if !h.NoSignature {
		locSig := ed25519.Sign(privKey, out[headerLength:])
		copy(out[headerLength-ed25519.SignatureSize:], locSig)
	}

	log.Printf("id: %d, elapsed: %s, request: %s, response: %s", id, time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}
