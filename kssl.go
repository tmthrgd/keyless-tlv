package main

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	humanize "github.com/dustin/go-humanize"
)

//go:generate stringer -type=Tag,Op -output=kssl_string.go

type GetCertificate func(op Operation) ([]byte, SKI, error)
type GetKey func(ski SKI) (crypto.Signer, error)

const (
	VersionMajor = 1
	VersionMinor = 0

	HeaderLength = 8

	PadTo = 1024
)

var padding [PadTo]byte

type Tag byte

const (
	TagDigest   Tag = 0x01 // [Deprecated]: SHA256 hash of RSA public key
	TagSNI      Tag = 0x02 // Server Name Identifier
	TagClientIP Tag = 0x03 // Client IP Address
	TagSKI      Tag = 0x04 // SHA1 hash of Subject Key Info
	TagServerIP Tag = 0x05 // Server IP Address
	TagSigAlgs  Tag = 0x06 // Signature Algorithms
	TagOpcode   Tag = 0x11 // Request operation code (see Op)
	TagPayload  Tag = 0x12 // Request/response payload
	TagPadding  Tag = 0x20 // Padding

	// The range [0xc0, 0xff) is reserved for private tags.
	TagECDSACipher Tag = 0xc0 // One iff ECDSA ciphers are supported
)

type Op uint16

const (
	// Decrypt data using RSA with or without padding
	OpRSADecrypt    Op = 0x0001
	OpRSADecryptRaw Op = 0x0008

	// Sign data using RSA
	OpRSASignMD5SHA1 Op = 0x0002
	OpRSASignSHA1    Op = 0x0003
	OpRSASignSHA224  Op = 0x0004
	OpRSASignSHA256  Op = 0x0005
	OpRSASignSHA384  Op = 0x0006
	OpRSASignSHA512  Op = 0x0007

	// Sign data using RSA-PSS
	OpRSAPSSSignSHA256 Op = 0x0035
	OpRSAPSSSignSHA384 Op = 0x0036
	OpRSAPSSSignSHA512 Op = 0x0037

	// Sign data using ECDSA
	OpECDSASignMD5SHA1 Op = 0x0012
	OpECDSASignSHA1    Op = 0x0013
	OpECDSASignSHA224  Op = 0x0014
	OpECDSASignSHA256  Op = 0x0015
	OpECDSASignSHA384  Op = 0x0016
	OpECDSASignSHA512  Op = 0x0017

	// Request a certificate and chain
	OpGetCertificate Op = 0x0020

	// [Deprecated]: A test message
	OpPing Op = 0x00F1
	OpPong Op = 0x00F2

	// [Deprecated]: A verification message
	OpActivate Op = 0x00F3

	// Response
	OpResponse Op = 0x00F0
	OpError    Op = 0x00FF

	// The range [0xc000, 0xffff) is reserved for private opcodes.
)

type Error uint16

const (
	ErrorCryptoFailed     Error = 0x0001 // Cryptographic error
	ErrorKeyNotFound      Error = 0x0002 // Private key not found
	ErrorDiskRead         Error = 0x0003 // [Deprecated]: Disk read failure
	ErrorVersionMismatch  Error = 0x0004 // Client-Server version mismatch
	ErrorBadOpcode        Error = 0x0005 // Invalid/unsupported opcode
	ErrorUnexpectedOpcode Error = 0x0006 // Opcode sent at wrong time/direction
	ErrorFormat           Error = 0x0007 // Malformed message
	ErrorInternal         Error = 0x0008 // Other internal error
	ErrorCertNotFound     Error = 0x0009 // Certificate not found

	// The range [0xc000, 0xffff) is reserved for private errors.
)

func (e Error) Error() string {
	switch e {
	case 0:
		return "no error"
	case ErrorCryptoFailed:
		return "cryptography error"
	case ErrorKeyNotFound:
		return "key not found"
	case ErrorDiskRead:
		return "disk read failure"
	case ErrorVersionMismatch:
		return "version mismatch"
	case ErrorBadOpcode:
		return "bad opcode"
	case ErrorUnexpectedOpcode:
		return "unexpected opcode"
	case ErrorFormat:
		return "malformed message"
	case ErrorInternal:
		return "internal error"
	case ErrorCertNotFound:
		return "certificate not found"
	default:
		return fmt.Sprintf("Error(%d)", e)
	}
}

type WrappedError struct {
	Code Error
	Err  error
}

func (e WrappedError) Error() string {
	return e.Code.Error() + ": " + e.Err.Error()
}

type Operation struct {
	Opcode             Op
	Payload            []byte
	SKI                SKI
	ClientIP, ServerIP net.IP
	SigAlgs            []byte
	SNI                []byte

	HasECDSACipher bool
}

func (op Operation) String() string {
	var ski2 []byte
	if op.SKI.Valid() {
		ski2 = op.SKI[:]
	}

	return fmt.Sprintf("Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SNI: %s, SigAlgs: %02x, ECDSA: %t", op.Opcode, ski2, op.ClientIP, op.ServerIP, op.SNI, op.SigAlgs, op.HasECDSACipher)
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

func handleRequest(in []byte, getCert GetCertificate, getKey GetKey, usePadding bool) (out []byte, err error) {
	start := time.Now()

	r := bytes.NewReader(in)

	major, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	var id uint32
	if err := binary.Read(r, binary.BigEndian, &id); err != nil {
		return nil, err
	}

	var op Operation

	if major != VersionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else if err = op.Unmarshal(in[HeaderLength:]); err == nil {
		log.Printf("id: %d, %v", id, op)

		op, err = processRequest(op, getCert, getKey)
	}

	var opcode Op

	if err != nil {
		log.Printf("id: %d, %v", id, err)

		opcode = OpError
	} else if op.Opcode != 0 {
		opcode = op.Opcode
	} else {
		opcode = OpResponse
	}

	b := bytes.NewBuffer(in[:0])
	b.Grow(1024 + 3)

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	// opcode tag
	b.WriteByte(byte(TagOpcode))

	if opcode > 0xff {
		binary.Write(b, binary.BigEndian, uint16(2))
		binary.Write(b, binary.BigEndian, uint16(opcode))
	} else {
		binary.Write(b, binary.BigEndian, uint16(1))
		b.WriteByte(byte(opcode))
	}

	if op.SKI.Valid() {
		// ski tag
		b.WriteByte(byte(TagSKI))
		binary.Write(b, binary.BigEndian, uint16(len(op.SKI)))
		b.Write(op.SKI[:])
	}

	// payload tag
	b.WriteByte(byte(TagPayload))

	if err != nil {
		errCode := ErrorInternal

		switch err := err.(type) {
		case Error:
			errCode = err
		case WrappedError:
			errCode = err.Code
		}

		if errCode > 0xff {
			binary.Write(b, binary.BigEndian, uint16(2))
			binary.Write(b, binary.BigEndian, uint16(errCode))
		} else {
			binary.Write(b, binary.BigEndian, uint16(1))
			b.WriteByte(byte(errCode))
		}
	} else {
		binary.Write(b, binary.BigEndian, uint16(len(op.Payload)))
		b.Write(op.Payload)
	}

	if usePadding && b.Len() < PadTo {
		toPad := PadTo - b.Len()

		b.WriteByte(byte(TagPadding))
		binary.Write(b, binary.BigEndian, uint16(toPad))
		b.Write(padding[:toPad])
	}

	out, err = b.Bytes(), nil
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-HeaderLength))

	log.Printf("id: %d, elapsed: %s, request: %s, response: %s", id, time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}
