package server

import (
	"crypto"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tmthrgd/keyless"
)

const bufferLength = 2 * 1024

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, bufferLength)
	},
}

var stdLogger = log.New(os.Stderr, "", log.LstdFlags)

type GetCertFunc func(op *keyless.Operation) (cert *keyless.Certificate, err error)
type GetKeyFunc func(ski keyless.SKI) (priv crypto.PrivateKey, err error)

type RequestHandler struct {
	GetCert GetCertFunc
	GetKey  GetKeyFunc

	IsAuthorised keyless.IsAuthorisedFunc

	ErrorLog *log.Logger

	SkipPadding bool
}

func (h *RequestHandler) logger() *log.Logger {
	if h.ErrorLog != nil {
		return h.ErrorLog
	}

	return stdLogger
}

func (h *RequestHandler) Handle(r io.Reader) (out []byte, err error) {
	start := time.Now()

	in := make([]byte, keyless.HeaderLength)
	if _, err = io.ReadFull(r, in); err != nil {
		return
	}

	var hdr keyless.Header
	if _, err = hdr.Unmarshal(in); err != nil {
		panic(err)
	}

	op := new(keyless.Operation)

	if hdr.Major != keyless.VersionMajor {
		err = keyless.ErrorVersionMismatch
	} else {
		if hdr.Length <= bufferLength {
			in = bufferPool.Get().([]byte)
			in = in[:hdr.Length]
		} else {
			in = make([]byte, hdr.Length)
		}

		if _, err = io.ReadFull(r, in); err == io.ErrUnexpectedEOF || err == io.EOF {
			err = keyless.WrappedError{keyless.ErrorFormat, io.ErrUnexpectedEOF}
		} else if err == nil {
			err = op.Unmarshal(in)
		}
	}

	if err == nil {
		h.logger().Printf("id: %d, %v", hdr.ID, op)

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(op)
		}

		if err == nil {
			op, err = h.Process(op)
		}
	}

	if err != nil {
		h.logger().Printf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	op.SkipPadding = h.SkipPadding

	out = hdr.Marshal(op, in[:0])

	if &out[0] != &in[0] && cap(in) == bufferLength {
		for i := range in {
			in[i] = 0
		}

		bufferPool.Put(in[:0])
	}

	h.logger().Printf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID,
		time.Since(start), keyless.HeaderLength+len(in), len(out))
	return
}

func (h *RequestHandler) HandleBytes(in []byte) (out []byte, err error) {
	start := time.Now()

	var hdr keyless.Header

	body, err := hdr.Unmarshal(in)
	if err != nil {
		return
	}

	op := new(keyless.Operation)

	switch {
	case hdr.Major != keyless.VersionMajor:
		err = keyless.ErrorVersionMismatch
	case int(hdr.Length) > len(body):
		err = keyless.WrappedError{keyless.ErrorFormat, io.ErrUnexpectedEOF}
	case int(hdr.Length) != len(body):
		err = keyless.WrappedError{keyless.ErrorFormat,
			errors.New("invalid header length")}
	default:
		err = op.Unmarshal(body)
	}

	if err == nil {
		h.logger().Printf("id: %d, %v", hdr.ID, op)

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(op)
		}

		if err == nil {
			op, err = h.Process(op)
		}
	}

	if err != nil {
		h.logger().Printf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	op.SkipPadding = h.SkipPadding

	out = hdr.Marshal(op, in[:0])

	h.logger().Printf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID,
		time.Since(start), len(in), len(out))
	return
}

func (h *RequestHandler) recv(addr net.Addr) {
	err := recover()
	if err == nil {
		return
	}

	const size = 64 << 10
	buf := make([]byte, size)
	buf = buf[:runtime.Stack(buf, false)]
	h.logger().Printf("panic serving %v: %v\n%s", addr, err, buf)
}

func (h *RequestHandler) ServePacket(conn net.PacketConn) error {
	for {
		buf := bufferPool.Get().([]byte)

		n, addr, err := conn.ReadFrom(buf[:cap(buf)])
		if err != nil {
			bufferPool.Put(buf[:0])

			if err == io.EOF {
				return nil
			}

			return err
		}

		go func(buf []byte, addr net.Addr) {
			defer h.recv(addr)

			out, err := h.HandleBytes(buf)
			if err != nil {
				h.logger().Printf("error: %v", err)
			} else if _, err = conn.WriteTo(out, addr); err != nil {
				h.logger().Printf("connection error: %v", err)
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
