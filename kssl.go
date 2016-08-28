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
	"fmt"
	"io"
	"log"
	"net"
)

//go:generate stringer -type=Tag,Op -output=kssl_string.go

type GetCertificate func(sni []byte, serverIP net.IP, payload []byte) (SKI, []byte, error, Error)
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
	OpRSADecryptRaw    = 0x08

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

func processRequest(in []byte, r *bytes.Reader, getCert GetCertificate, getKey GetKey) (outSKI SKI, out []byte, err error, err2 Error) {
	var opcode Op
	var payload []byte
	var ski SKI
	var clientIP, serverIP net.IP
	var sni []byte

	seen := make(map[Tag]struct{})

	for r.Len() != 0 {
		tag, err := r.ReadByte()
		if err != nil {
			return nilSKI, nil, err, ErrorFormat
		}

		var length uint16
		if err = binary.Read(r, binary.BigEndian, &length); err != nil {
			return nilSKI, nil, err, ErrorFormat
		}

		if int(length) > r.Len() {
			return nilSKI, nil, fmt.Errorf("%s length is %dB beyond end of body", tag, int(length)-r.Len()), ErrorFormat
		}

		if _, ok := seen[Tag(tag)]; ok {
			return nilSKI, nil, fmt.Errorf("tag %s seen multiple times", tag), ErrorFormat
		}
		seen[Tag(tag)] = struct{}{}

		offset, err := r.Seek(int64(length), io.SeekCurrent)
		if err != nil {
			return nilSKI, nil, err, ErrorInternal
		}

		data := in[offset-int64(length) : offset]

		switch Tag(tag) {
		case TagDigest:
			if len(data) != sha256.Size {
				return nilSKI, nil, nil, ErrorFormat
			}
		case TagSNI:
			sni = data
		case TagClientIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				return nilSKI, nil, nil, ErrorFormat
			}

			clientIP = data
		case TagSKI:
			if len(data) != sha1.Size {
				return nilSKI, nil, nil, ErrorFormat
			}

			copy(ski[:], data)
		case TagServerIP:
			if len(data) != net.IPv4len && len(data) != net.IPv6len {
				return nilSKI, nil, nil, ErrorFormat
			}

			serverIP = data
		case TagOpcode:
			if len(data) != 1 {
				return nilSKI, nil, nil, ErrorFormat
			}

			opcode = Op(data[0])
		case TagPayload:
			payload = data
		case TagPadding:
			// ignore; should this be checked to ensure it is zero?
		default:
			return nilSKI, nil, fmt.Errorf("unknown tag: %s", tag), ErrorFormat
		}
	}

	var ski2 []byte
	if ski.Valid() {
		ski2 = ski[:]
	}

	log.Printf("Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SNI: %s", opcode, ski2, clientIP, serverIP, sni)

	var opts crypto.SignerOpts
	var key crypto.Signer
	var ok bool

	switch opcode {
	case OpPing:
		return nilSKI, payload, nil, ErrorNone
	case OpGetCertificate:
		if getCert == nil {
			return nilSKI, nil, nil, ErrorCertNotFound
		}

		return getCert(sni, serverIP, payload)
	case OpRSADecrypt, OpRSADecryptRaw:
		if getKey == nil {
			return nilSKI, nil, nil, ErrorKeyNotFound
		}

		if key, ok = getKey(ski); !ok {
			return nilSKI, nil, nil, ErrorKeyNotFound
		}

		if _, ok = key.Public().(*rsa.PublicKey); !ok {
			return nilSKI, nil, fmt.Errorf("Key is not RSA"), ErrorCryptoFailed
		}

		var ptxt []byte

		if opcode == OpRSADecryptRaw {
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nilSKI, nil, fmt.Errorf("Key is not rsa.PrivateKey"), ErrorCryptoFailed
			}

			ptxt, err = rsaRawDecrypt(rand.Reader, rsaKey, payload)
		} else {
			rsaKey, ok := key.(crypto.Decrypter)
			if !ok {
				return nilSKI, nil, fmt.Errorf("Key is not Decrypter"), ErrorCryptoFailed
			}

			ptxt, err = rsaKey.Decrypt(rand.Reader, payload, nil)
		}

		if err != nil {
			return nilSKI, nil, err, ErrorCryptoFailed
		}

		return nilSKI, ptxt, nil, ErrorNone
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
		return nilSKI, nil, nil, ErrorUnexpectedOpcode
	default:
		return nilSKI, nil, nil, ErrorBadOpcode
	}

	if getKey == nil {
		return nilSKI, nil, nil, ErrorKeyNotFound
	}

	if key, ok = getKey(ski); !ok {
		return nilSKI, nil, nil, ErrorKeyNotFound
	}

	// Ensure we don't perform an ECDSA/RSA sign for an RSA/ECDSA request.
	switch opcode {
	case OpRSASignMD5SHA1, OpRSASignSHA1, OpRSASignSHA224, OpRSASignSHA256, OpRSASignSHA384, OpRSASignSHA512,
		OpRSAPSSSignSHA256, OpRSAPSSSignSHA384, OpRSAPSSSignSHA512:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return nilSKI, nil, fmt.Errorf("request is RSA, but key isn't"), ErrorCryptoFailed
		}
	case OpECDSASignMD5SHA1, OpECDSASignSHA1, OpECDSASignSHA224, OpECDSASignSHA256, OpECDSASignSHA384, OpECDSASignSHA512:
		if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
			return nilSKI, nil, fmt.Errorf("request is ECDSA, but key isn't"), ErrorCryptoFailed
		}
	}

	sig, err := key.Sign(rand.Reader, payload, opts)
	if err != nil {
		return nilSKI, nil, err, ErrorCryptoFailed
	}

	return nilSKI, sig, nil, ErrorNone
}

func handleRequest(buf []byte, getCert GetCertificate, getKey GetKey) (out []byte, err error) {
	r := bytes.NewReader(buf)

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

	err2 := ErrorNone

	if major != VersionMajor {
		err2 = ErrorVersionMismatch
	}

	if err2 == ErrorNone && int(length) != r.Len() {
		err2 = ErrorFormat
	}

	var ski SKI
	var payload []byte
	if err2 == ErrorNone {
		if ski, payload, err, err2 = processRequest(buf, r, getCert, getKey); err != nil {
			log.Println(err)

			if err2 == ErrorNone {
				err2 = ErrorInternal
			}
		}
	}

	b := bytes.NewBuffer(buf[:0])

	b.WriteByte(VersionMajor)
	b.WriteByte(VersionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	// opcode tag
	b.WriteByte(byte(TagOpcode))
	binary.Write(b, binary.BigEndian, uint16(1))

	if err2 == ErrorNone {
		b.WriteByte(byte(OpResponse))
	} else {
		b.WriteByte(byte(OpError))
	}

	if ski.Valid() {
		// ski tag
		b.WriteByte(byte(TagSKI))
		binary.Write(b, binary.BigEndian, uint16(len(ski)))
		b.Write(ski[:])
	}

	// payload tag
	b.WriteByte(byte(TagPayload))

	if err2 == ErrorNone {
		binary.Write(b, binary.BigEndian, uint16(len(payload)))
		b.Write(payload)
	} else {
		binary.Write(b, binary.BigEndian, uint16(1))
		b.WriteByte(byte(err2))
	}

	if b.Len() < PadTo {
		toPad := PadTo - b.Len()

		b.WriteByte(byte(TagPadding))
		binary.Write(b, binary.BigEndian, uint16(toPad))
		b.Write(padding[:toPad])
	}

	out = b.Bytes()
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-HeaderLength))
	return
}
