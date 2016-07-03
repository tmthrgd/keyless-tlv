package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	reuseport "github.com/jbenet/go-reuseport"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2*1024)
	},
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	var addr string
	flag.StringVar(&addr, "addr", "127.0.0.1:2407", "the address to listen on")

	var dir string
	flag.StringVar(&dir, "dir", "/etc/nginx/ssl", "the directory to serve keys and certs from")

	var pid string
	flag.StringVar(&pid, "pid", "/run/keyless.pid", "the file to write the pid out to")

	flag.Parse()

	var conn net.PacketConn
	var err error

	if reuseport.Available() {
		conn, err = reuseport.ListenPacket("udp", addr)
	} else {
		conn, err = net.ListenPacket("udp", addr)
	}

	if err != nil {
		panic(err)
	}

	defer conn.Close()

	if pid != "" {
		if f, err := os.Create(pid); err != nil {
			log.Printf("error creating pid file: %v", err)
		} else {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
		}
	}

	keys := newKeyLoader()
	certs := newCertLoader()

	s := newServer(keys, certs.CertLoader)

	if err = keys.LoadFromDir(dir); err != nil {
		panic(err)
	}

	if err = certs.LoadFromDir(dir); err != nil {
		panic(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)

		for range c {
			log.Println("Received SIGHUP, reloading keys...")

			if err := keys.LoadFromDir(dir); err != nil {
				panic(err)
			}

			if err := certs.LoadFromDir(dir); err != nil {
				panic(err)
			}
		}
	}()

	log.Printf("listening on %s\n", addr)

	for {
		buf := bufferPool.Get().([]byte)

		n, addr, err := conn.ReadFrom(buf[:cap(buf)])
		if err != nil {
			bufferPool.Put(buf[:0])

			log.Println(err)
			continue
		}

		go func(buf []byte, addr net.Addr) {
			start := time.Now()

			out, err := s.Handle(buf)
			if err != nil {
				log.Printf("error: %v\n", err)

				bufferPool.Put(buf[:0])
				return
			}

			elapsed := time.Since(start)
			log.Printf("took %s", elapsed)

			if _, err = conn.WriteTo(out, addr); err != nil {
				log.Printf("connection error: %v\n", err)
			}

			for i := 0; i < len(out); i++ {
				out[i] = 0
			}

			for i := 0; i < len(buf); i++ {
				buf[i] = 0
			}

			bufferPool.Put(buf[:0])
		}(buf[:n], addr)
	}
}
