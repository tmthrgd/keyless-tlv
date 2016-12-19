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
	"golang.org/x/crypto/ed25519"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	humanize "github.com/dustin/go-humanize"
)

var usePadding bool = true

type GetCertificate func(op *Operation) ([]byte, SKI, error)
type GetKey func(ski SKI) (crypto.Signer, error)

const (
	Version2Major = 2
	Version2Minor = 0

	Version1Major = 1
	Version1Minor = 0

	HeaderLength2 = 8 + 8 + ed25519.SignatureSize + ed25519.PublicKeySize + ed25519.SignatureSize
	HeaderLength1 = 8

	PadTo = 1024
)

var (
	padding [PadTo]byte
	nilSig  [ed25519.SignatureSize]byte
)

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

	return fmt.Sprintf("Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SNI: %s, SigAlgs: %02x, ECDSA: %t", op.Opcode, ski2, op.ClientIP, op.ServerIP, op.SNI, op.SigAlgs, op.HasECDSACipher)
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

type RequestHandler struct {
	sync.RWMutex

	GetCert GetCertificate
	GetKey  GetKey

	PublicKey  publicKey
	PrivateKey ed25519.PrivateKey

	Authority struct {
		ID, Signature []byte
	}

	Authorities Authorities

	V1 bool
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	headerLength, versionMajor, versionMinor := HeaderLength2, byte(Version2Major), byte(Version2Minor)
	if h.V1 {
		headerLength, versionMajor, versionMinor = HeaderLength1, Version1Major, Version1Minor
	}

	r := bytes.NewReader(in)

	var major byte
	if major, err = r.ReadByte(); err != nil {
		return
	}

	if _, err = r.ReadByte(); err != nil {
		return
	}

	var length uint16
	if err = binary.Read(r, binary.BigEndian, &length); err != nil {
		return
	}

	var id uint32
	if err = binary.Read(r, binary.BigEndian, &id); err != nil {
		return
	}

	var remAuthID [8]byte
	var remAuthSig, remSig [ed25519.SignatureSize]byte
	var remPublic [ed25519.PublicKeySize]byte

	if !h.V1 {
		if _, err = r.Read(remAuthID[:]); err != nil {
			return
		}

		if _, err = r.Read(remAuthSig[:]); err != nil {
			return
		}

		if _, err = r.Read(remPublic[:]); err != nil {
			return
		}

		if _, err = r.Read(remSig[:]); err != nil {
			return
		}
	}

	h.RLock()

	op := new(Operation)

	if major != versionMajor {
		err = ErrorVersionMismatch
	} else if int(length) != r.Len() {
		err = WrappedError{ErrorFormat, errors.New("invalid header length")}
	} else if !h.V1 && !ed25519.Verify(remPublic[:], in[headerLength:], remSig[:]) {
		err = WrappedError{ErrorNotAuthorised, errors.New("invalid signature")}
	} else if authority, ok := h.Authorities.Get(remAuthID[:]); !h.V1 && !(ok &&
		ed25519.Verify(authority, remPublic[:], remAuthSig[:])) {
		err = WrappedError{
			Code: ErrorNotAuthorised,
			Err:  fmt.Errorf("%s not authorised", publicKey(remPublic[:])),
		}
	} else if err = op.Unmarshal(in[headerLength:]); err == nil {
		if h.V1 {
			log.Printf("id: %d, %v", id, op)
		} else {
			log.Printf("id: %d, key: %s, %v", id, publicKey(remPublic[:]), op)
		}

		op, err = h.process(op)
	}

	if err != nil {
		log.Printf("id: %d, %v", id, err)

		*op = Operation{
			Opcode: OpError,
		}

		errCode := ErrorInternal

		switch err := err.(type) {
		case Error:
			errCode = err
		case WrappedError:
			errCode = err.Code
		}

		if errCode > 0xff {
			op.Payload = make([]byte, 2)
			binary.BigEndian.PutUint16(op.Payload, uint16(errCode))
		} else {
			op.Payload = []byte{byte(errCode)}
		}
	} else if op.Opcode == 0 {
		op.Opcode = OpResponse
	}

	b := bytes.NewBuffer(in[:0])
	b.Grow(PadTo + 3)

	b.WriteByte(versionMajor)
	b.WriteByte(versionMinor)
	binary.Write(b, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(b, binary.BigEndian, id)

	if !h.V1 {
		b.Write(h.Authority.ID)
		b.Write(h.Authority.Signature)
		b.Write(h.PublicKey)
		b.Write(nilSig[:]) // signature placeholder
	}

	op.Marshal(b)

	out, err = b.Bytes(), nil
	binary.BigEndian.PutUint16(out[2:], uint16(b.Len()-headerLength))

	if !h.V1 {
		locSig := ed25519.Sign(h.PrivateKey, out[headerLength:])
		copy(out[headerLength-ed25519.SignatureSize:headerLength], locSig)
	}

	h.RUnlock()

	log.Printf("id: %d, elapsed: %s, request: %s, response: %s", id, time.Since(start),
		humanize.IBytes(uint64(len(in))), humanize.IBytes(uint64(len(out))))
	return
}

func (h *RequestHandler) ReadKeyFile(path string) error {
	keyfile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	const expectedSize = ed25519.PrivateKeySize + 8 + ed25519.SignatureSize
	if len(keyfile) != expectedSize {
		return fmt.Errorf("invalid key file: expected length %d, got length %d", expectedSize, len(keyfile))
	}

	h.Lock()

	h.PrivateKey = keyfile[:ed25519.PrivateKeySize]
	h.PublicKey = publicKey(h.PrivateKey.Public().(ed25519.PublicKey))

	h.Authority.ID = keyfile[ed25519.PrivateKeySize : ed25519.PrivateKeySize+8]
	h.Authority.Signature = keyfile[ed25519.PrivateKeySize+8:]

	h.Unlock()
	return nil
}
