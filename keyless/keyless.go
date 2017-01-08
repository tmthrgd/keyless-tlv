package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/ed25519"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/jbenet/go-reuseport"
	"github.com/tmthrgd/keyless"
	"github.com/tmthrgd/keyless/server"
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

	var stapleOCSP bool
	flag.BoolVar(&stapleOCSP, "ocsp", false, "staple OCSP responses")

	var selfSign bool
	flag.BoolVar(&selfSign, "self-sign", false, "return self signed certificates for unkown server names")

	var acmeKeyPath string
	flag.StringVar(&acmeKeyPath, "acme", "", "the path to the ACME client key")

	var acmeURL string
	flag.StringVar(&acmeURL, "acme-url", acme.LetsEncryptURL, "the ACME directory URL")

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

	keys := server.NewKeyLoader()
	certs := server.NewCertLoader()
	auths := keyless.NewAuthorities()

	getCert := certs.GetCertificate
	getKey := keys.GetKey

	if selfSign {
		ss := server.NewSelfSigner()

		getCert = (server.GetCertChain{getCert, ss.GetCertificate}).GetCertificate
		getKey = (server.GetKeyChain{getKey, ss.GetKey}).GetKey
	}

	if len(acmeKeyPath) != 0 {
		in, err := ioutil.ReadFile(acmeKeyPath)
		if err != nil {
			panic(err)
		}

		priv, err := helpers.ParsePrivateKeyPEM(in)
		if err != nil {
			priv, err = derhelpers.ParsePrivateKeyDER(in)
			if err != nil {
				panic(err)
			}
		}

		ac := server.NewACMEClient(&acme.Client{
			Key: priv,

			DirectoryURL: acmeURL,
		})

		getCert = (server.GetCertChain{getCert, ac.GetCertificate}).GetCertificate
		getKey = (server.GetKeyChain{getKey, ac.GetKey}).GetKey
	}

	if stapleOCSP {
		ocsp := server.NewOCSPRequester(getCert)
		getCert = ocsp.GetCertificate
	}

	handler := &server.RequestHandler{
		GetCert: getCert,
		GetKey:  getKey,

		IsAuthorised: auths.IsAuthorised,
	}

	var reload = func() error {
		if err := keys.LoadFromDir(dir); err != nil {
			return err
		}

		if err := certs.LoadFromDir(dir); err != nil {
			return err
		}

		if err := auths.ReadFrom(authoritiesPath); err != nil {
			return err
		}

		return handler.ReadKeyFile(keyfilePath)
	}

	if err = reload(); err != nil {
		panic(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)

		for range c {
			log.Println("Received SIGHUP, reloading keys...")

			if err := reload(); err != nil {
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
