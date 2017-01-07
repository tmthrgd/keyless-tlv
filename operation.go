package keyless

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const PadTo = 1024

var padding [PadTo]byte

type Operation struct {
	Opcode             Op
	Payload            []byte
	SKI                SKI
	ClientIP, ServerIP net.IP
	SigAlgs            []byte
	SNI                []byte

	OCSPResponse  []byte
	Authorisation []byte

	HasECDSACipher bool

	errorBuffer [2]byte

	SkipPadding bool
}

func (op *Operation) String() string {
	return fmt.Sprintf("Opcode: %s, SKI: %s, Client IP: %s, Server IP: %s, SNI: %s, SigAlgs: %02x, ECDSA: %t",
		op.Opcode, op.SKI, op.ClientIP, op.ServerIP, op.SNI, op.SigAlgs, op.HasECDSACipher)
}

func (op *Operation) Marshal(ow io.Writer) error {
	lw := &lenWriter{W: ow}
	w := &errWriter{W: lw}

	// opcode tag
	binary.Write(w, binary.BigEndian, uint16(TagOpcode))
	binary.Write(w, binary.BigEndian, uint16(2))
	binary.Write(w, binary.BigEndian, uint16(op.Opcode))

	if op.SKI.Valid() {
		// ski tag
		binary.Write(w, binary.BigEndian, uint16(TagSKI))
		binary.Write(w, binary.BigEndian, uint16(len(op.SKI)))
		w.Write(op.SKI[:])
	}

	if op.ClientIP != nil {
		// client ip tag
		binary.Write(w, binary.BigEndian, uint16(TagClientIP))
		binary.Write(w, binary.BigEndian, uint16(len(op.ClientIP)))
		w.Write(op.ClientIP)
	}

	if op.ServerIP != nil {
		// server ip tag
		binary.Write(w, binary.BigEndian, uint16(TagServerIP))
		binary.Write(w, binary.BigEndian, uint16(len(op.ServerIP)))
		w.Write(op.ServerIP)
	}

	if op.SNI != nil {
		// sni tag
		binary.Write(w, binary.BigEndian, uint16(TagSNI))
		binary.Write(w, binary.BigEndian, uint16(len(op.SNI)))
		w.Write(op.SNI)
	}

	if op.SigAlgs != nil {
		// signature algorithms tag
		binary.Write(w, binary.BigEndian, uint16(TagSigAlgs))
		binary.Write(w, binary.BigEndian, uint16(len(op.SigAlgs)))
		w.Write(op.SigAlgs)
	}

	if op.OCSPResponse != nil {
		// ocsp response tag
		binary.Write(w, binary.BigEndian, uint16(TagOCSPResponse))
		binary.Write(w, binary.BigEndian, uint16(len(op.OCSPResponse)))
		w.Write(op.OCSPResponse)
	}

	if op.Authorisation != nil {
		// authorisation tag
		binary.Write(w, binary.BigEndian, uint16(TagAuthorisation))
		binary.Write(w, binary.BigEndian, uint16(len(op.Authorisation)))
		w.Write(op.Authorisation)
	}

	if op.HasECDSACipher {
		// ecdsa cipher tag
		binary.Write(w, binary.BigEndian, uint16(TagECDSACipher))
		binary.Write(w, binary.BigEndian, uint16(1))
		w.Write([]byte{0x01})
	}

	if op.Payload != nil {
		// payload tag
		binary.Write(w, binary.BigEndian, uint16(TagPayload))
		binary.Write(w, binary.BigEndian, uint16(len(op.Payload)))
		w.Write(op.Payload)
	}

	if !op.SkipPadding && lw.N < PadTo {
		toPad := PadTo - lw.N

		// padding tag
		binary.Write(w, binary.BigEndian, uint16(TagPadding))
		binary.Write(w, binary.BigEndian, uint16(toPad))
		w.Write(padding[:toPad])
	}

	return w.Err
}

func (op *Operation) Unmarshal(in []byte) error {
	*op = Operation{}

	seen := make(map[Tag]struct{})

	for len(in) != 0 {
		if len(in) < 4 {
			return WrappedError{ErrorFormat, errors.New("missing tag and length")}
		}

		tag := Tag(binary.BigEndian.Uint16(in))
		length := binary.BigEndian.Uint16(in[2:])
		in = in[4:]

		if int(length) > len(in) {
			return WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", tag, int(length)-len(in))}
		}

		if _, saw := seen[tag]; saw {
			return WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", tag)}
		}
		seen[tag] = struct{}{}

		switch tag {
		case TagDigest:
			if length != sha256.Size {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 32 bytes, was %d bytes", TagDigest, length)}
			}
		case TagSNI:
			op.SNI = in[:length:length]
		case TagClientIP:
			if length != net.IPv4len && length != net.IPv6len {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 4 or 16 bytes, was %d bytes", TagClientIP, length)}
			}

			op.ClientIP = in[:length:length]
		case TagSKI:
			if length != sha1.Size {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 20 bytes, was %d bytes", TagSKI, length)}
			}

			copy(op.SKI[:], in)
		case TagServerIP:
			if length != net.IPv4len && length != net.IPv6len {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 4 or 16 bytes, was %d bytes", TagServerIP, length)}
			}

			op.ServerIP = in[:length:length]
		case TagSigAlgs:
			if length%2 != 0 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be even number of bytes, was %d bytes", TagSigAlgs, length)}
			}

			op.SigAlgs = in[:length:length]
		case TagOpcode:
			if length != 2 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 2 bytes, was %d bytes", TagOpcode, length)}
			}

			op.Opcode = Op(binary.BigEndian.Uint16(in))
		case TagPayload:
			op.Payload = in[:length:length]
		case TagPadding:
			var v byte

			for i := 0; i < int(length); i++ {
				v |= in[i]
			}

			if subtle.ConstantTimeByteEq(v, 0) == 0 {
				return WrappedError{ErrorFormat, errors.New("invalid padding")}
			}
		case TagOCSPResponse:
			op.OCSPResponse = in[:length:length]
		case TagAuthorisation:
			op.Authorisation = in[:length:length]
		case TagECDSACipher:
			if length != 1 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 byte, was %d bytes", TagECDSACipher, length)}
			}

			op.HasECDSACipher = in[0]&0x01 != 0
		}

		in = in[length:]
	}

	return nil
}

func (op *Operation) FromError(err error) {
	*op = Operation{
		Opcode:  OpError,
		Payload: op.errorBuffer[:],
	}
	binary.BigEndian.PutUint16(op.Payload, uint16(getErrorCode(err)))
}
