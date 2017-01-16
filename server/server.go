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

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2*1024)
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

func (h *RequestHandler) Handle(in []byte) (out []byte, err error) {
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

	if op.Opcode == 0 {
		op.Opcode = keyless.OpResponse
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

			out, err := h.Handle(buf)
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
