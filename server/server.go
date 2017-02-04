package server

import (
	"bytes"
	"crypto"
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

	var hdrBuf [keyless.HeaderLength]byte
	if _, err = io.ReadFull(r, hdrBuf[:]); err != nil {
		return
	}

	var hdr keyless.Header
	if _, err = hdr.Unmarshal(hdrBuf[:]); err != nil {
		panic(err)
	}

	var in []byte
	op := new(keyless.Operation)

	if hdr.Version != keyless.Version {
		atomic.AddUint64(&h.Stats.versionErrorss, 1)

		err = keyless.ErrorVersionMismatch
	} else {
		atomic.AddUint64(&h.Stats.requests, 1)

		if hdr.Length == 0 || hdr.Length > bufferLength {
			in = make([]byte, hdr.Length)
		} else {
			in = bufferPool.Get().([]byte)
			in = in[:hdr.Length]
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

	buf := bufferPool.Get().([]byte)
	if out, err = hdr.Marshal(op, buf[:0]); err != nil {
		op.FromError(err)
		op.SkipPadding = h.SkipPadding

		if out, err = hdr.Marshal(op, buf[:0]); err != nil {
			// should be impossible
			panic(err)
		}
	}

	for i := range in {
		in[i] = 0
	}

	if cap(in) == bufferLength {
		bufferPool.Put(in[:0])
	}

	if buf := buf[:cap(buf)]; &buf[0] != &out[0] {
		for i := range buf {
			buf[i] = 0
		}

		bufferPool.Put(buf[:0])
	}

	h.logger().Printf("id: %d, elapsed: %s, request: %d B, response: %d B", hdr.ID,
		time.Since(start), keyless.HeaderLength+len(in), len(out))
	return
}

func (h *RequestHandler) HandleBytes(in []byte) (out []byte, err error) {
	return h.Handle(bytes.NewReader(in))
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

			if cap(out) == bufferLength {
				bufferPool.Put(out[:0])
			}

			bufferPool.Put(buf[:0])
		}(buf[:n], addr)
	}
}
