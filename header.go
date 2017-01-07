package keyless

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/ed25519"
)

var nilSig [ed25519.SignatureSize]byte

type Header struct {
	Major, Minor byte
	Length       uint16
	ID           uint32

	PublicKey ed25519.PublicKey
	Signature []byte

	NoSignature bool
}

func (h *Header) Marshal(op *Operation, priv ed25519.PrivateKey, buf []byte) []byte {
	b := bytes.NewBuffer(buf)
	b.Grow(PadTo + 4)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, h.ID)

	if !h.NoSignature {
		b.Write(h.PublicKey)
		b.Write(nilSig[:]) // signature placeholder
	}

	hdrLen := b.Len()

	op.Marshal(b)

	out := b.Bytes()
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-hdrLen))

	if !h.NoSignature {
		locSig := ed25519.Sign(priv, out[hdrLen:])
		copy(out[hdrLen-ed25519.SignatureSize:], locSig)
	}

	return out
}

func (h *Header) Unmarshal(in []byte) (rest []byte, err error) {
	const (
		headerLength            = 8 + ed25519.PublicKeySize + ed25519.SignatureSize
		headerLengthNoSignature = 8
	)

	if (h.NoSignature && len(in) < headerLengthNoSignature) ||
		(!h.NoSignature && len(in) < headerLength) {
		return nil, errors.New("missing header")
	}

	h.Major, h.Minor = in[0], in[1]
	h.Length = binary.BigEndian.Uint16(in[2:])
	h.ID = binary.BigEndian.Uint32(in[4:])

	in = in[headerLengthNoSignature:]

	if !h.NoSignature {
		h.PublicKey, in = in[:ed25519.PublicKeySize:ed25519.PublicKeySize], in[ed25519.PublicKeySize:]
		h.Signature, in = in[:ed25519.SignatureSize:ed25519.SignatureSize], in[ed25519.SignatureSize:]
	}

	return in, nil
}
