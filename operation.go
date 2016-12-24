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

const PadTo = 1024

var (
	padding [PadTo]byte

	usePadding bool = true
)

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
}

func (op *Operation) String() string {
	return fmt.Sprintf("Opcode: %s, SKI: %s, Client IP: %s, Server IP: %s, SNI: %s, SigAlgs: %02x, ECDSA: %t",
		op.Opcode, op.SKI, op.ClientIP, op.ServerIP, op.SNI, op.SigAlgs, op.HasECDSACipher)
}

type Writer interface {
	io.Writer
	io.ByteWriter

	Len() int
}

func (op *Operation) Marshal(w Writer) {
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
		w.WriteByte(byte(TagSigAlgs))
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
		w.WriteByte(0x01)
	}

	if op.Payload != nil {
		// payload tag
		binary.Write(w, binary.BigEndian, uint16(TagPayload))
		binary.Write(w, binary.BigEndian, uint16(len(op.Payload)))
		w.Write(op.Payload)
	}

	if usePadding && w.Len() < PadTo {
		toPad := PadTo - w.Len()

		// padding tag
		binary.Write(w, binary.BigEndian, uint16(TagPadding))
		binary.Write(w, binary.BigEndian, uint16(toPad))
		w.Write(padding[:toPad])
	}
}

func (op *Operation) Unmarshal(in []byte) error {
	*op = Operation{}

	r := bytes.NewReader(in)

	seen := make(map[Tag]struct{})

	for r.Len() != 0 {
		var tag Tag
		if err := binary.Read(r, binary.BigEndian, (*uint16)(&tag)); err != nil {
			return WrappedError{ErrorFormat, err}
		}

		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return WrappedError{ErrorFormat, err}
		}

		if int(length) > r.Len() {
			return WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", tag, int(length)-r.Len())}
		}

		if _, saw := seen[tag]; saw {
			return WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", tag)}
		}
		seen[tag] = struct{}{}

		offset, err := r.Seek(int64(length), io.SeekCurrent)
		if err != nil {
			return WrappedError{ErrorInternal, err}
		}

		data := in[offset-int64(length) : offset]

		switch tag {
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
			if len(data) != 2 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 2 bytes, was %d bytes", TagOpcode, len(data))}
			}

			op.Opcode = Op(binary.BigEndian.Uint16(data))
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
		case TagOCSPResponse:
			op.OCSPResponse = data
		case TagAuthorisation:
			op.Authorisation = data
		case TagECDSACipher:
			if len(data) != 1 {
				return WrappedError{ErrorFormat, fmt.Errorf("%s should be 1 byte, was %d bytes", TagECDSACipher, len(data))}
			}

			op.HasECDSACipher = data[0]&0x01 != 0
		}
	}

	return nil
}

func (op *Operation) FromError(err error) {
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
}
