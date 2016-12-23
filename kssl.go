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

const (
	VersionMajor = 2
	VersionMinor = 0

	HeaderLength            = 8 + 8 + ed25519.SignatureSize + ed25519.PublicKeySize + ed25519.SignatureSize
	HeaderLengthNoSignature = 8
)

var nilSig [ed25519.SignatureSize]byte

type RequestHandler struct {
	sync.RWMutex

	GetCert func(op *Operation) (out []byte, ski SKI, OCSP []byte, err error)
	GetKey  func(ski SKI) (priv crypto.Signer, err error)

	PublicKey  PublicKey
	PrivateKey ed25519.PrivateKey

	Authority struct {
		ID, Signature []byte
	}

	Authorities Authorities

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

	var remAuthID [8]byte
	var remAuthSig, remSig [ed25519.SignatureSize]byte
	var remPublic [ed25519.PublicKeySize]byte

	if !h.NoSignature {
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

	authority, authorityOk := ed25519.PublicKey(nil), false
	var authID, authSig []byte
	pubKey, privKey := PublicKey(nil), ed25519.PrivateKey(nil)

	if !h.NoSignature {
		h.RLock()

		authority, authorityOk = h.Authorities.Get(remAuthID[:])

		authID, authSig = h.Authority.ID, h.Authority.Signature
		pubKey, privKey = h.PublicKey, h.PrivateKey

		h.RUnlock()
	}

	op := new(Operation)

	if major != VersionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else if !h.NoSignature &&
		!ed25519.Verify(remPublic[:], in[headerLength:], remSig[:]) {
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
	} else if !h.NoSignature &&
		!(authorityOk && ed25519.Verify(authority, remPublic[:], remAuthSig[:])) {
		err = WrappedError{
			Code: ErrorNotAuthorised,
			Err:  fmt.Errorf("%s not authorised", PublicKey(remPublic[:])),
		}
	} else if err = op.Unmarshal(in[headerLength:]); err == nil {
		if h.NoSignature {
			log.Printf("id: %d, %v", id, op)
		} else {
			log.Printf("id: %d, key: %s, %v", id, PublicKey(remPublic[:]), op)
		}

		op, err = h.Process(op)
	}

	if err != nil {
		log.Printf("id: %d, %v", id, err)

		*op = Operation{
			Opcode:  OpError,
			Payload: op.errorBuffer[:],
		}

		errCode := ErrorInternal

		switch err := err.(type) {
		case Error:
			errCode = err
		case WrappedError:
			errCode = err.Code
		}

		binary.BigEndian.PutUint16(op.Payload, uint16(errCode))
	} else if op.Opcode == 0 {
		op.Opcode = OpResponse
	}

	b := bytes.NewBuffer(in[:0])
	b.Grow(PadTo + 3)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	if !h.NoSignature {
		b.Write(authID)
		b.Write(authSig)
		b.Write(pubKey)
		b.Write(nilSig[:]) // signature placeholder
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
