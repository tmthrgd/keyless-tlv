package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/crypto/acme"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/jbenet/go-reuseport"
	"github.com/tmthrgd/keyless/server"
	kacme "github.com/tmthrgd/keyless/server/acme"
	"github.com/tmthrgd/keyless/server/ocsp"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	if err := disableTracing(); err != nil {
		panic(err)
	}

	var addr string
	flag.StringVar(&addr, "addr", "127.0.0.1:2407", "the address to listen on")

	var dir string
	flag.StringVar(&dir, "dir", "/etc/nginx/ssl", "the directory to serve keys and certs from")

	var pid string
	flag.StringVar(&pid, "pid", "/run/keyless.pid", "the file to write the pid out to")

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

		ac := kacme.NewClient(&acme.Client{
			Key: priv,

			DirectoryURL: acmeURL,
		})

		getCert = (server.GetCertChain{getCert, ac.GetCertificate}).GetCertificate
		getKey = (server.GetKeyChain{getKey, ac.GetKey}).GetKey
	}

	if stapleOCSP {
		ocsp := ocsp.NewRequester(getCert)
		getCert = ocsp.GetCertificate
	}

	handler := &server.RequestHandler{
		GetCert: getCert,
		GetKey:  getKey,
	}

	var reload = func() error {
		if err := keys.LoadFromDir(dir); err != nil {
			return err
		}

		return certs.LoadFromDir(dir)
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

			log.Printf("listening on %s\n", addr)
		}
	}()

	log.Printf("listening on %s\n", addr)

	panic(handler.ServePacket(conn))
}
