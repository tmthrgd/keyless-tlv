package server

import (
	"crypto"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/tmthrgd/keyless"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2*1024)
	},
}

type GetCertFunc func(op *keyless.Operation) (cert *keyless.Certificate, err error)
type GetKeyFunc func(ski keyless.SKI) (priv crypto.PrivateKey, err error)

type RequestHandler struct {
	GetCert GetCertFunc
	GetKey  GetKeyFunc

	sync.RWMutex
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	Authorisation []byte

	IsAuthorised keyless.IsAuthorisedFunc

	ErrorLog *log.Logger

	NoSignature bool
	SkipPadding bool
}

func (h *RequestHandler) logf(format string, args ...interface{}) {
	if h.ErrorLog != nil {
		h.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
	start := time.Now()

	hdr := keyless.Header{NoSignature: h.NoSignature}

	body, err := hdr.Unmarshal(in)
	if err != nil {
		return
	}

	op := new(keyless.Operation)

	switch {
	case hdr.Major != keyless.VersionMajor:
		err = keyless.ErrorVersionMismatch
	case int(hdr.Length) != len(body):
		err = keyless.WrappedError{keyless.ErrorFormat,
			errors.New("invalid header length")}
	case !h.NoSignature && !ed25519.Verify(hdr.PublicKey, body, hdr.Signature):
		err = keyless.WrappedError{keyless.ErrorNotAuthorised,
			errors.New("invalid signature")}
	default:
		err = op.Unmarshal(body)
	}

	if err == nil {
		if h.NoSignature {
			h.logf("id: %d, %v", hdr.ID, op)
		} else {
			h.logf("id: %d, key: %s, %v", hdr.ID,
				base64.RawStdEncoding.EncodeToString(hdr.PublicKey), op)
		}

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(hdr.PublicKey, op)
		}

		if err == nil {
			op, err = h.Process(op)
		}
	}

	if err != nil {
		h.logf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	if op.Opcode == 0 {
		op.Opcode = keyless.OpResponse
	}

	op.SkipPadding = h.SkipPadding

	var privKey ed25519.PrivateKey

	if !h.NoSignature {
		h.RLock()
		hdr.PublicKey, privKey = h.PublicKey, h.PrivateKey
		op.Authorisation = h.Authorisation
		h.RUnlock()
	}

	out = hdr.Marshal(op, privKey, in[:0])

	h.logf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID, time.Since(start), len(in), len(out))
	return
}

func (h *RequestHandler) ServePacket(conn net.PacketConn) error {
	for {
		buf := bufferPool.Get().([]byte)

		n, addr, err := conn.ReadFrom(buf[:cap(buf)])
		if err != nil {
			bufferPool.Put(buf[:0])
			return err
		}

		go func(buf []byte, addr net.Addr) {
			out, err := h.Handle(buf)
			if err != nil {
				h.logf("error: %v", err)
			} else if _, err = conn.WriteTo(out, addr); err != nil {
				h.logf("connection error: %v", err)
			}

			for i := range out {
				out[i] = 0
			}

			for i := range buf {
				buf[i] = 0
			}

			bufferPool.Put(buf[:0])
		}(buf[:n], addr)
	}
}
