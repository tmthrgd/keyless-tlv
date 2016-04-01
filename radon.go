package main

import (
	"crypto"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	gkserver "github.com/cloudflare/gokeyless/server"
)

const (
	addr = "127.0.0.1:9674"
	//addr  = "/var/radon.sock"
	owner  = "www-data"
	perms  = 0660
	keyDir = "/etc/nginx/ssl"
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
	if addr[0] == '/' {
		os.Remove(addr)
	}

	conn, err := net.ListenPacket("udp", addr)

	if err != nil {
		panic(err)
	}

	if _, ok := conn.(*net.UnixConn); ok {
		defer os.Remove(addr)
		defer conn.Close()

		user, err := user.Lookup(owner)

		if err != nil {
			panic(err)
		}

		uid, err := strconv.Atoi(user.Uid)

		if err != nil {
			panic(err)
		}

		gid, err := strconv.Atoi(user.Gid)

		if err != nil {
			panic(err)
		}

		if err = syscall.Chown(addr, uid, gid); err != nil {
			panic(err)
		}

		if err = syscall.Chmod(addr, perms); err != nil {
			panic(err)
		}
	} else {
		defer conn.Close()
	}

	/*if pidFile != "" {
		if f, err := os.Create(pidFile); err != nil {
			log.Errorf("error creating pid file: %v", err)
		} else {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
		}
	}*/

	s := newServer(gkserver.NewKeystore())

	if err = s.LoadKeysFromDir(keyDir, loadKey); err != nil {
		panic(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)

		for range c {
			log.Println("Received SIGHUP, reloading keys...")

			if err := s.LoadKeysFromDir(keyDir, loadKey); err != nil {
				panic(err)
			}
		}
	}()

	/*go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		signal.Notify(c, syscall.SIGTERM)

		<-c

		os.Exit(1)
	}()*/

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
