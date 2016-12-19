package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

var padding [PadTo]byte

type Operation struct {
	Opcode             Op
	Payload            []byte
	SKI                SKI
	ClientIP, ServerIP net.IP
	SigAlgs            []byte
	SNI                []byte

	HasECDSACipher bool
}

func (op *Operation) String() string {
	var ski2 []byte
	if op.SKI.Valid() {
		ski2 = op.SKI[:]
	}

	return fmt.Sprintf("Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SNI: %s, SigAlgs: %02x, ECDSA: %t",
		op.Opcode, ski2, op.ClientIP, op.ServerIP, op.SNI, op.SigAlgs, op.HasECDSACipher)
}

type Writer interface {
	io.Writer
	io.ByteWriter

	Len() int
}

func (op *Operation) Marshal(w Writer) {
	// opcode tag
	w.WriteByte(byte(TagOpcode))

	if op.Opcode > 0xff {
		binary.Write(w, binary.BigEndian, uint16(2))
		binary.Write(w, binary.BigEndian, uint16(op.Opcode))
	} else {
		binary.Write(w, binary.BigEndian, uint16(1))
		w.WriteByte(byte(op.Opcode))
	}

	if op.SKI.Valid() {
		// ski tag
		w.WriteByte(byte(TagSKI))
		binary.Write(w, binary.BigEndian, uint16(len(op.SKI)))
		w.Write(op.SKI[:])
	}

	if op.ClientIP != nil {
		// client ip tag
		w.WriteByte(byte(TagClientIP))
		binary.Write(w, binary.BigEndian, uint16(len(op.ClientIP)))
		w.Write(op.ClientIP)
	}

	if op.ServerIP != nil {
		// server ip tag
		w.WriteByte(byte(TagServerIP))
		binary.Write(w, binary.BigEndian, uint16(len(op.ServerIP)))
		w.Write(op.ServerIP)
	}

	if op.SNI != nil {
		// sni tag
		w.WriteByte(byte(TagSNI))
		binary.Write(w, binary.BigEndian, uint16(len(op.SNI)))
		w.Write(op.SNI)
	}

	if op.SigAlgs != nil {
		// signature algorithms tag
		w.WriteByte(byte(TagSigAlgs))
		binary.Write(w, binary.BigEndian, uint16(len(op.SigAlgs)))
		w.Write(op.SigAlgs)
	}

	if op.Payload != nil {
		// payload tag
		w.WriteByte(byte(TagPayload))
		binary.Write(w, binary.BigEndian, uint16(len(op.Payload)))
		w.Write(op.Payload)
	}

	if usePadding && w.Len() < PadTo {
		toPad := PadTo - w.Len()

		// padding tag
		w.WriteByte(byte(TagPadding))
		binary.Write(w, binary.BigEndian, uint16(toPad))
		w.Write(padding[:toPad])
	}
}

func (op *Operation) Unmarshal(in []byte) error {
	*op = Operation{}

	r := bytes.NewReader(in)

	seen := make(map[Tag]struct{})

	for r.Len() != 0 {
		tag, err := r.ReadByte()
		if err != nil {
			return WrappedError{ErrorFormat, err}
		}

		var length uint16
		if err = binary.Read(r, binary.BigEndian, &length); err != nil {
			return WrappedError{ErrorFormat, err}
		}

		if int(length) > r.Len() {
			return WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", Tag(tag), int(length)-r.Len())}
		}

		if _, saw := seen[Tag(tag)]; saw {
			return WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", Tag(tag))}
		}
		seen[Tag(tag)] = struct{}{}

		offset, err := r.Seek(int64(length), io.SeekCurrent)
		if err != nil {
			return WrappedError{ErrorInternal, err}
		}

		data := in[offset-int64(length) : offset]

		switch Tag(tag) {
		case TagDigest:
			if len(data) != sha256.Size {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 32 bytes, was %d bytes", TagDigest, len(data))}
			}
		case TagSNI:
			op.SNI = data
		case TagClientIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 4 or 16 bytes, was %d bytes", TagClientIP, len(data))}
			}

			op.ClientIP = data
		case TagSKI:
			if len(data) != sha1.Size {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 20 bytes, was %d bytes", TagSKI, len(data))}
			}

			copy(op.SKI[:], data)
		case TagServerIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 4 or 16 bytes, was %d bytes", TagServerIP, len(data))}
			}

			op.ServerIP = data
		case TagSigAlgs:
			if len(data)%2 != 0 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be even number of bytes, was %d bytes", TagSigAlgs, len(data))}
			}

			op.SigAlgs = data
		case TagOpcode:
			switch len(data) {
			case 1:
				op.Opcode = Op(data[0])
			case 2:
				op.Opcode = Op(binary.BigEndian.Uint16(data))

				if op.Opcode < 0x100 {
					return WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 bytes for opcodes in [0x00, 0xff], was 2 bytes", TagOpcode)}
				}
			default:
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 or 2 bytes, was %d bytes", TagOpcode, len(data))}
			}
		case TagPayload:
			op.Payload = data
		case TagPadding:
			var v byte

			for i := 0; i < len(data); i++ {
				v |= data[i]
			}

			if subtle.ConstantTimeByteEq(v, 0) == 0 {
				return WrappedError{ErrorFormat, errors.New("invalid padding")}
			}
		case TagECDSACipher:
			if len(data) != 1 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 byte, was %d bytes", TagECDSACipher, len(data))}
			}

			op.HasECDSACipher = data[0]&0x01 != 0
		}
	}

	return nil
}
