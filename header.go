package main

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/ed25519"
)

var nilSig [ed25519.SignatureSize]byte

type Header struct {
	Major, Minor byte
	Length       uint16
	ID           uint32

	PublicKey ed25519.PublicKey
	Signature []byte

	PrivateKey ed25519.PrivateKey

	pubBuffer [ed25519.PublicKeySize]byte
	sigBuffer [ed25519.SignatureSize]byte

	NoSignature bool
}

func (h *Header) Marshal(op *Operation, buf []byte) []byte {
	b := bytes.NewBuffer(buf)
	b.Grow(PadTo + 3)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, h.ID)

	if !h.NoSignature {
		b.Write(h.PublicKey)
		b.Write(nilSig[:]) // signature placeholder
	}

	op.Marshal(b)

	out := b.Bytes()

	if h.NoSignature {
		binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-HeaderLengthNoSignature))
	} else {
		binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-HeaderLength))

		locSig := ed25519.Sign(h.PrivateKey, out[HeaderLength:])
		copy(out[HeaderLength-ed25519.SignatureSize:], locSig)
	}

	return out
}

func (h *Header) Unmarshal(r *bytes.Reader) (err error) {
	if h.Major, err = r.ReadByte(); err != nil {
		return
	}

	if h.Minor, err = r.ReadByte(); err != nil {
		return
	}

	if err = binary.Read(r, binary.BigEndian, &h.Length); err != nil {
		return
	}

	if err = binary.Read(r, binary.BigEndian, &h.ID); err != nil {
		return
	}

	if h.NoSignature {
		return
	}

	h.PublicKey, h.Signature = h.pubBuffer[:], h.sigBuffer[:]

	if _, err = r.Read(h.PublicKey); err != nil {
		return
	}

	_, err = r.Read(h.Signature)
	return
}
