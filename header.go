package keyless

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const HeaderLength = 8

var nilLen24 [3]byte

type Header struct {
	Version byte
	Length  uint32
	ID      uint32
}

func (h *Header) Marshal(op *Operation, buf []byte) ([]byte, error) {
	b := bytes.NewBuffer(buf)
	b.Grow(HeaderLength + PadTo + 4)

	b.WriteByte(Version)
	b.Write(nilLen24[:]) // length placeholder
	binary.Write(b, binary.BigEndian, h.ID)

	if err := op.Marshal(b); err != nil {
		return nil, err
	}

	out := b.Bytes()
	l := len(out) - HeaderLength

	const maxUint24 = 0xffffff
	if l > maxUint24 {
		return nil, errors.New("body too large")
	}

	out[1] = byte(l >> 16)
	out[2] = byte(l >> 8)
	out[3] = byte(l)
	return out, nil
}

func (h *Header) Unmarshal(in []byte) (rest []byte, err error) {
	if len(in) < HeaderLength {
		return nil, errors.New("missing header")
	}

	h.Version = in[0]
	h.Length = uint32(in[3]) | uint32(in[2])<<8 | uint32(in[1])<<16
	h.ID = binary.BigEndian.Uint32(in[4:])

	return in[HeaderLength:], nil
}
