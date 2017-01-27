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
	"sync/atomic"
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

	Stats RequestHandlerStats
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
		atomic.AddUint64(&h.Stats.versionErrorss, 1)

		err = keyless.ErrorVersionMismatch
	} else {
		atomic.AddUint64(&h.Stats.requests, 1)

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
			if err != nil {
				atomic.AddUint64(&h.Stats.unmarshal, 1)
			}
		}
	}

	if err == nil {
		h.logger().Printf("id: %d, %v", hdr.ID, op)

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(op)
			if keyless.GetErrorCode(err) == keyless.ErrorNotAuthorised {
				atomic.AddUint64(&h.Stats.unauthorised, 1)
			}
		}

		if err == nil {
			op, err = h.Process(op)
			if err != nil {
				atomic.AddUint64(&h.Stats.process, 1)
			}
		}
	}

	if err != nil {
		if keyless.GetErrorCode(err) == keyless.ErrorFormat {
			atomic.AddUint64(&h.Stats.formatErrors, 1)
		}

		h.logger().Printf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	op.SkipPadding = h.SkipPadding

	if out, err = hdr.Marshal(op, in[:0]); err != nil {
		op.FromError(err)
		op.SkipPadding = h.SkipPadding

		if out, err = hdr.Marshal(op, in[:0]); err != nil {
			// should be impossible
			panic(err)
		}
	}

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

	atomic.AddUint64(&h.Stats.requests, 1)

	op := new(keyless.Operation)

	switch {
	case hdr.Major != keyless.VersionMajor:
		atomic.AddUint64(&h.Stats.versionErrorss, 1)

		err = keyless.ErrorVersionMismatch
	case int(hdr.Length) > len(body):
		err = keyless.WrappedError{keyless.ErrorFormat, io.ErrUnexpectedEOF}
	case int(hdr.Length) != len(body):
		err = keyless.WrappedError{keyless.ErrorFormat,
			errors.New("invalid header length")}
	default:
		err = op.Unmarshal(body)
		if err != nil {
			atomic.AddUint64(&h.Stats.unmarshal, 1)
		}
	}

	if err == nil {
		h.logger().Printf("id: %d, %v", hdr.ID, op)

		if h.IsAuthorised != nil {
			err = h.IsAuthorised(op)
			if keyless.GetErrorCode(err) == keyless.ErrorNotAuthorised {
				atomic.AddUint64(&h.Stats.unauthorised, 1)
			}
		}

		if err == nil {
			op, err = h.Process(op)
			if err != nil {
				atomic.AddUint64(&h.Stats.process, 1)
			}
		}
	}

	if err != nil {
		if keyless.GetErrorCode(err) == keyless.ErrorFormat {
			atomic.AddUint64(&h.Stats.formatErrors, 1)
		}

		h.logger().Printf("id: %d, %v", hdr.ID, err)

		op.FromError(err)
		err = nil
	}

	op.SkipPadding = h.SkipPadding

	if out, err = hdr.Marshal(op, in[:0]); err != nil {
		op.FromError(err)
		op.SkipPadding = h.SkipPadding

		if out, err = hdr.Marshal(op, in[:0]); err != nil {
			// should be impossible
			panic(err)
		}
	}

	h.logger().Printf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID,
		time.Since(start), len(in), len(out))
	return
}

func (h *RequestHandler) recv(addr net.Addr) {
	err := recover()
	if err == nil {
		return
	}

	atomic.AddUint64(&h.Stats.panics, 1)

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
