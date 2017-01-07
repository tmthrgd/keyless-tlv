package keyless

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/ed25519"
)

const (
	HeaderLength            = 8 + ed25519.PublicKeySize + ed25519.SignatureSize
	HeaderLengthNoSignature = 8
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

		locSig := ed25519.Sign(priv, out[HeaderLength:])
		copy(out[HeaderLength-ed25519.SignatureSize:], locSig)
	}

	return out
}

func (h *Header) Unmarshal(in []byte) (rest []byte, err error) {
	if (h.NoSignature && len(in) < HeaderLengthNoSignature) ||
		(!h.NoSignature && len(in) < HeaderLength) {
		return nil, errors.New("missing header")
	}

	h.Major, h.Minor = in[0], in[1]
	h.Length = binary.BigEndian.Uint16(in[2:])
	h.ID = binary.BigEndian.Uint32(in[4:])

	in = in[HeaderLengthNoSignature:]

	if !h.NoSignature {
		h.PublicKey, in = in[:ed25519.PublicKeySize:ed25519.PublicKeySize], in[ed25519.PublicKeySize:]
		h.Signature, in = in[:ed25519.SignatureSize:ed25519.SignatureSize], in[ed25519.SignatureSize:]
	}

	return in, nil
}
