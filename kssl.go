package main

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	humanize "github.com/dustin/go-humanize"
)

type GetCertificate func(op *Operation) ([]byte, SKI, error)
type GetKey func(ski SKI) (crypto.Signer, error)

const (
	Version2Major = 2
	Version2Minor = 0

	Version1Major = 1
	Version1Minor = 0

	HeaderLength2 = 8 + 8 + ed25519.SignatureSize + ed25519.PublicKeySize + ed25519.SignatureSize
	HeaderLength1 = 8
)

var nilSig [ed25519.SignatureSize]byte

type RequestHandler struct {
	sync.RWMutex

	GetCert GetCertificate
	GetKey  GetKey

	PublicKey  publicKey
	PrivateKey ed25519.PrivateKey

	Authority struct {
		ID, Signature []byte
	}

	Authorities Authorities

	V1 bool
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	headerLength, versionMajor, versionMinor := HeaderLength2, byte(Version2Major), byte(Version2Minor)
	if h.V1 {
		headerLength, versionMajor, versionMinor = HeaderLength1, Version1Major, Version1Minor
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

	var remAuthID [8]byte
	var remAuthSig, remSig [ed25519.SignatureSize]byte
	var remPublic [ed25519.PublicKeySize]byte

	if !h.V1 {
		if _, err = r.Read(remAuthID[:]); err != nil {
			return
		}

		if _, err = r.Read(remAuthSig[:]); err != nil {
			return
		}

		if _, err = r.Read(remPublic[:]); err != nil {
			return
		}

		if _, err = r.Read(remSig[:]); err != nil {
			return
		}
	}

	h.RLock()

	op := new(Operation)

	if major != versionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else if !h.V1 && !ed25519.Verify(remPublic[:], in[headerLength:], remSig[:]) {
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
	} else if authority, ok := h.Authorities.Get(remAuthID[:]); !h.V1 && !(ok &&
		ed25519.Verify(authority, remPublic[:], remAuthSig[:])) {
		err = WrappedError{
			Code: ErrorNotAuthorised,
			Err:  fmt.Errorf("%s not authorised", publicKey(remPublic[:])),
		}
	} else if err = op.Unmarshal(in[headerLength:]); err == nil {
		if h.V1 {
			log.Printf("id: %d, %v", id, op)
		} else {
			log.Printf("id: %d, key: %s, %v", id, publicKey(remPublic[:]), op)
		}

		op, err = h.process(op)
	}

	if err != nil {
		log.Printf("id: %d, %v", id, err)

		*op = Operation{
			Opcode: OpError,
		}

		errCode := ErrorInternal

		switch err := err.(type) {
		case Error:
			errCode = err
		case WrappedError:
			errCode = err.Code
		}

		if errCode > 0xff {
			op.Payload = make([]byte, 2)
			binary.BigEndian.PutUint16(op.Payload, uint16(errCode))
		} else {
			op.Payload = []byte{byte(errCode)}
		}
	} else if op.Opcode == 0 {
		op.Opcode = OpResponse
	}

	b := bytes.NewBuffer(in[:0])
	b.Grow(PadTo + 3)

	b.WriteByte(versionMajor)
	b.WriteByte(versionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	if !h.V1 {
		b.Write(h.Authority.ID)
		b.Write(h.Authority.Signature)
		b.Write(h.PublicKey)
		b.Write(nilSig[:]) // signature placeholder
	}

	op.Marshal(b)

	out, err = b.Bytes(), nil
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-headerLength))

	if !h.V1 {
		locSig := ed25519.Sign(h.PrivateKey, out[headerLength:])
		copy(out[headerLength-ed25519.SignatureSize:headerLength], locSig)
	}

	h.RUnlock()

	log.Printf("id: %d, elapsed: %s, request: %s, response: %s", id, time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}
