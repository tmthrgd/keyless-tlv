package main

import (
	"crypto"
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

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	gkserver "github.com/cloudflare/gokeyless/server"
	reuseport "github.com/jbenet/go-reuseport"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2*1024)
	},
}

func loadKey(in []byte) (crypto.Signer, error) {
	if priv, err := helpers.ParsePrivateKeyPEM(in); err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	var addr string
	flag.StringVar(&addr, "addr", "127.0.0.1:9674", "the address to listen on")

	var dir string
	flag.StringVar(&dir, "dir", "/etc/nginx/ssl", "the directory to serve keys from")

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

	s := newServer(gkserver.NewKeystore())

	if err = s.LoadKeysFromDir(dir, loadKey); err != nil {
		panic(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)

		for range c {
			log.Println("Received SIGHUP, reloading keys...")

			if err := s.LoadKeysFromDir(dir, loadKey); err != nil {
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
			defer bufferPool.Put(buf[:0])

			start := time.Now()

			out, err := s.Handle(buf)

			if err != nil {
				log.Printf("error: %v\n", err)
				return
			}

			if _, err = conn.WriteTo(out, addr); err != nil {
				log.Printf("connection error: %v\n", err)
			}

			elapsed := time.Since(start)
			log.Printf("took %s", elapsed)
		}(buf[:n], addr)
	}
}
