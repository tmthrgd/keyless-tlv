package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/jbenet/go-reuseport"
	"github.com/tmthrgd/keyless"
	"golang.org/x/crypto/ed25519"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2*1024)
	},
}

func publicKeyString(k ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(k)
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

	var keyfilePath string
	flag.StringVar(&keyfilePath, "keyfile", "/etc/keyless.key", "the file to read the ed25519 key from")

	var authoritiesPath string
	flag.StringVar(&authoritiesPath, "authorities", "/etc/keyless.auth", "the file to read authorities from")

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

	keys := keyless.NewKeyLoader()
	certs := keyless.NewCertLoader()
	auths := keyless.NewAuthorities()

	if err = keys.LoadFromDir(dir); err != nil {
		panic(err)
	}

	if err = certs.LoadFromDir(dir); err != nil {
		panic(err)
	}

	if err := auths.ReadFrom(authoritiesPath); err != nil {
		panic(err)
	}

	handler := &keyless.RequestHandler{
		GetCert: certs.GetCertificate,
		GetKey:  keys.GetKey,

		IsAuthorised: auths.IsAuthorised,
	}

	if err := handler.ReadKeyFile(keyfilePath); err != nil {
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

			if err := auths.ReadFrom(authoritiesPath); err != nil {
				panic(err)
			}

			if err := handler.ReadKeyFile(keyfilePath); err != nil {
				panic(err)
			}

			log.Printf("listening on %s with key %s\n", addr,
				publicKeyString(handler.PublicKey))
		}
	}()

	log.Printf("listening on %s with key %s\n", addr, publicKeyString(handler.PublicKey))

	for {
		buf := bufferPool.Get().([]byte)

		n, addr, err := conn.ReadFrom(buf[:cap(buf)])
		if err != nil {
			bufferPool.Put(buf[:0])

			log.Println(err)
			continue
		}

		go func(buf []byte, addr net.Addr) {
			out, err := handler.Handle(buf)
			if err != nil {
				log.Printf("error: %v\n", err)
			} else if _, err = conn.WriteTo(out, addr); err != nil {
				log.Printf("connection error: %v\n", err)
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
