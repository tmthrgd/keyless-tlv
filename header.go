package keyless

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const HeaderLength = 8

type Header struct {
	Major, Minor byte
	Length       uint16
	ID           uint32
}

func (h *Header) Marshal(op *Operation, buf []byte) ([]byte, error) {
	b := bytes.NewBuffer(buf)
	b.Grow(HeaderLength + PadTo + 4)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, h.ID)

	if err := op.Marshal(b); err != nil {
		return nil, err
	}

	out := b.Bytes()
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)-HeaderLength))

	if len(out)-HeaderLength > maxUint16 {
		return nil, errors.New("body too large")
	}

	return out, nil
}

func (h *Header) Unmarshal(in []byte) (rest []byte, err error) {
	if len(in) < HeaderLength {
		return nil, errors.New("missing header")
	}

	h.Major, h.Minor = in[0], in[1]
	h.Length = binary.BigEndian.Uint16(in[2:])
	h.ID = binary.BigEndian.Uint32(in[4:])

	return in[HeaderLength:], nil
}
