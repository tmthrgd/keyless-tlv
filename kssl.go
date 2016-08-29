package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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

type GetCertificate func(ski SKI, sni []byte, serverIP net.IP, payload []byte) ([]byte, SKI, error)
type GetKey func(ski SKI) (crypto.Signer, bool)

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
	TagOpcode   Tag = 0x11 // Request operation code (see Op)
	TagPayload  Tag = 0x12 // Request/response payload
	TagPadding  Tag = 0x20 // Padding
)

type Op byte

const (
	// Decrypt data using RSA with or without padding
	OpRSADecrypt    Op = 0x01
	OpRSADecryptRaw Op = 0x08

	// Sign data using RSA
	OpRSASignMD5SHA1 Op = 0x02
	OpRSASignSHA1    Op = 0x03
	OpRSASignSHA224  Op = 0x04
	OpRSASignSHA256  Op = 0x05
	OpRSASignSHA384  Op = 0x06
	OpRSASignSHA512  Op = 0x07

	// Sign data using RSA-PSS
	OpRSAPSSSignSHA256 Op = 0x35
	OpRSAPSSSignSHA384 Op = 0x36
	OpRSAPSSSignSHA512 Op = 0x37

	// Sign data using ECDSA
	OpECDSASignMD5SHA1 Op = 0x12
	OpECDSASignSHA1    Op = 0x13
	OpECDSASignSHA224  Op = 0x14
	OpECDSASignSHA256  Op = 0x15
	OpECDSASignSHA384  Op = 0x16
	OpECDSASignSHA512  Op = 0x17

	// Request a certificate and chain
	OpGetCertificate Op = 0x20

	// [Deprecated]: A test message
	OpPing Op = 0xF1
	OpPong Op = 0xF2

	// [Deprecated]: A verification message
	OpActivate Op = 0xF3

	// Response
	OpResponse Op = 0xF0
	OpError    Op = 0xFF
)

type Error byte

const (
	ErrorNone             Error = iota // No error
	ErrorCryptoFailed                  // Cryptographic error
	ErrorKeyNotFound                   // Private key not found
	ErrorDiskRead                      // [Deprecated]: Disk read failure
	ErrorVersionMismatch               // Client-Server version mismatch
	ErrorBadOpcode                     // Invalid/unsupported opcode
	ErrorUnexpectedOpcode              // Opcode sent at wrong time/direction
	ErrorFormat                        // Malformed message
	ErrorInternal                      // Other internal error
	ErrorCertNotFound                  // Certificate not found
)

func (e Error) Error() string {
	switch e {
	case ErrorNone:
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
		return "unkown error"
	}
}

type WrappedError struct {
	Code Error
	Err  error
}

func (e WrappedError) Error() string {
	return e.Code.Error() + ": " + e.Err.Error()
}

func processRequest(in []byte, r *bytes.Reader, getCert GetCertificate, getKey GetKey) (out []byte, outSKI SKI, ping bool, err error) {
	var opcode Op
	var payload []byte
	var ski SKI
	var clientIP, serverIP net.IP
	var sni []byte

	seen := make(map[Tag]struct{})

	for r.Len() != 0 {
		var tag byte
		if tag, err = r.ReadByte(); err != nil {
			err = WrappedError{ErrorFormat, err}
			return
		}

		var length uint16
		if err = binary.Read(r, binary.BigEndian, &length); err != nil {
			err = WrappedError{ErrorFormat, err}
			return
		}

		if int(length) > r.Len() {
			err = WrappedError{ErrorFormat, fmt.Errorf("%s length is %dB beyond end of body", tag, int(length)-r.Len())}
			return
		}

		if _, saw := seen[Tag(tag)]; saw {
			err = WrappedError{ErrorFormat, fmt.Errorf("tag %s seen multiple times", tag)}
			return
		}
		seen[Tag(tag)] = struct{}{}

		var offset int64
		if offset, err = r.Seek(int64(length), io.SeekCurrent); err != nil {
			err = WrappedError{ErrorInternal, err}
			return
		}

		data := in[offset-int64(length) : offset]

		switch Tag(tag) {
		case TagDigest:
			if len(data) != sha256.Size {
				err = ErrorFormat
				return
			}
		case TagSNI:
			sni = data
		case TagClientIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				err = ErrorFormat
				return
			}

			clientIP = data
		case TagSKI:
			if len(data) != sha1.Size {
				err = ErrorFormat
				return
			}

			copy(ski[:], data)
		case TagServerIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				err = ErrorFormat
				return
			}

			serverIP = data
		case TagOpcode:
			if len(data) != 1 {
				err = ErrorFormat
				return
			}

			opcode = Op(data[0])
		case TagPayload:
			payload = data
		case TagPadding:
			// ignore; should this be checked to ensure it is zero?
		default:
			err = WrappedError{ErrorFormat, fmt.Errorf("unknown tag: %s", tag)}
			return
		}
	}

	var ski2 []byte
	if ski.Valid() {
		ski2 = ski[:]
	}

	log.Printf("Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SNI: %s", opcode, ski2, clientIP, serverIP, sni)

	var opts crypto.SignerOpts

	switch opcode {
	case OpPing:
		out, ping = payload, true
		return
	case OpGetCertificate:
		if getCert == nil {
			err = ErrorCertNotFound
			return
		}

		out, outSKI, err = getCert(ski, sni, serverIP, payload)
		return
	case OpRSADecrypt, OpRSADecryptRaw:
		if getKey == nil {
			err = ErrorKeyNotFound
			return
		}

		key, ok := getKey(ski)
		if !ok {
			err = ErrorKeyNotFound
			return
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("Key is not RSA")}
			return
		}

		if opcode == OpRSADecryptRaw {
			out, err = rsaRawDecrypt(rand.Reader, rsaKey, payload)
		} else {
			out, err = rsaKey.Decrypt(rand.Reader, payload, nil)
		}

		if err != nil {
			err = WrappedError{ErrorCryptoFailed, err}
		}

		return
	case OpRSASignMD5SHA1, OpECDSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case OpRSASignSHA1, OpECDSASignSHA1:
		opts = crypto.SHA1
	case OpRSASignSHA224, OpECDSASignSHA224:
		opts = crypto.SHA224
	case OpRSASignSHA256, OpECDSASignSHA256:
		opts = crypto.SHA256
	case OpRSASignSHA384, OpECDSASignSHA384:
		opts = crypto.SHA384
	case OpRSASignSHA512, OpECDSASignSHA512:
		opts = crypto.SHA512
	case OpRSAPSSSignSHA256:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA256}
	case OpRSAPSSSignSHA384:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA384}
	case OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA512}
	//case gokeyless.OpActivate:
	case OpPong, OpResponse, OpError:
		err = ErrorUnexpectedOpcode
		return
	default:
		err = ErrorBadOpcode
		return
	}

	if getKey == nil {
		err = ErrorKeyNotFound
		return
	}

	key, ok := getKey(ski)
	if !ok {
		err = ErrorKeyNotFound
		return
	}

	// Ensure we don't perform an ECDSA/RSA sign for an RSA/ECDSA request.
	switch opcode {
	case OpRSASignMD5SHA1, OpRSASignSHA1, OpRSASignSHA224, OpRSASignSHA256, OpRSASignSHA384, OpRSASignSHA512,
		OpRSAPSSSignSHA256, OpRSAPSSSignSHA384, OpRSAPSSSignSHA512:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is RSA, but key isn't")}
			return
		}
	case OpECDSASignMD5SHA1, OpECDSASignSHA1, OpECDSASignSHA224, OpECDSASignSHA256, OpECDSASignSHA384, OpECDSASignSHA512:
		if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is ECDSA, but key isn't")}
			return
		}
	}

	if out, err = key.Sign(rand.Reader, payload, opts); err != nil {
		err = WrappedError{ErrorCryptoFailed, err}
	}

	return
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

	var payload []byte
	var ski SKI
	var ping bool

	if major != VersionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else {
		payload, ski, ping, err = processRequest(in, r, getCert, getKey)
	}

	if err != nil {
		log.Println(err)
	}

	b := bytes.NewBuffer(in[:0])

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	// opcode tag
	b.WriteByte(byte(TagOpcode))
	binary.Write(b, binary.BigEndian, uint16(1))

	if err != nil && err != ErrorNone {
		b.WriteByte(byte(OpError))
	} else if ping {
		b.WriteByte(byte(OpPong))
	} else {
		b.WriteByte(byte(OpResponse))
	}

	if ski.Valid() {
		// ski tag
		b.WriteByte(byte(TagSKI))
		binary.Write(b, binary.BigEndian, uint16(len(ski)))
		b.Write(ski[:])
	}

	// payload tag
	b.WriteByte(byte(TagPayload))

	if err != nil && err != ErrorNone {
		binary.Write(b, binary.BigEndian, uint16(1))

		switch err := err.(type) {
		case Error:
			b.WriteByte(byte(err))
		case WrappedError:
			b.WriteByte(byte(err.Code))
		default:
			b.WriteByte(byte(ErrorInternal))
		}

		err = nil
	} else {
		binary.Write(b, binary.BigEndian, uint16(len(payload)))
		b.Write(payload)
	}

	if usePadding && b.Len() < PadTo {
		toPad := PadTo - b.Len()

		b.WriteByte(byte(TagPadding))
		binary.Write(b, binary.BigEndian, uint16(toPad))
		b.Write(padding[:toPad])
	}

	out = b.Bytes()
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-HeaderLength))

	log.Printf("elapsed: %s, request: %s, response: %s", time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}
