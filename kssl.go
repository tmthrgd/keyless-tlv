package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/cloudflare/gokeyless"
	gkserver "github.com/cloudflare/gokeyless/server"
)

const OpRSADecryptRaw gokeyless.Op = 0x08

func encodeOperation(id uint32, operation *gokeyless.Operation) ([]byte, error) {
	h := gokeyless.NewHeader(operation)
	h.ID = id
	return h.MarshalBinary()
}

func encodeResponse(id uint32, payload []byte) ([]byte, error) {
	return encodeOperation(id, &gokeyless.Operation{
		Opcode:  gokeyless.OpResponse,
		Payload: payload,
	})
}

func encodeError(id uint32, err gokeyless.Error) ([]byte, error) {
	return encodeOperation(id, &gokeyless.Operation{
		Opcode:  gokeyless.OpError,
		Payload: []byte{byte(err)},
	})
}

type server struct {
	keys gkserver.Keystore
	cert gkserver.CertLoader
}

func newServer(keys gkserver.Keystore, certLoader gkserver.CertLoader) server {
	return server{keys, certLoader}
}

func (s server) Handle(buf []byte) (out []byte, err error) {
	h := new(gokeyless.Header)

	if err = h.UnmarshalBinary(buf); err != nil {
		return
	}

	if 8+int(h.Length) > len(buf) {
		log.Printf("%s: Header length is %dB beyond end of buffer", gokeyless.ErrFormat, 8+int(h.Length)-len(buf))

		return encodeError(h.ID, gokeyless.ErrFormat)
	}

	h.Body = new(gokeyless.Operation)

	if err = h.Body.UnmarshalBinary(buf[8 : 8+h.Length]); err != nil {
		log.Println(err)

		return encodeError(h.ID, gokeyless.ErrFormat)
	}

	var ski []byte
	if h.Body.SKI.Valid() {
		ski = h.Body.SKI[:]
	}

	log.Printf("version:%d.%d id:%d body:[Opcode: %s, SKI: %02x, Client IP: %s, Server IP: %s, SigAlgs: %02x, SNI: %s]",
		h.MajorVers, h.MinorVers,
		h.ID,
		h.Body.Opcode,
		ski,
		h.Body.ClientIP,
		h.Body.ServerIP,
		h.Body.SigAlgs,
		h.Body.SNI)

	var opts crypto.SignerOpts
	var key crypto.Signer
	var ok bool

	switch h.Body.Opcode {
	case gokeyless.OpPing:
		return encodeOperation(h.ID, &gokeyless.Operation{
			Opcode:  gokeyless.OpPong,
			Payload: h.Body.Payload,
		})
	case gokeyless.OpCertificateRequest:
		if s.cert == nil {
			log.Println(gokeyless.ErrCertNotFound)

			return encodeError(h.ID, gokeyless.ErrCertNotFound)
		}

		if !h.Body.SigAlgs.Valid() {
			log.Println(gokeyless.ErrFormat)

			return encodeError(h.ID, gokeyless.ErrFormat)
		}

		certChain, err := s.cert(h.Body.SigAlgs, h.Body.ServerIP, h.Body.SNI)
		switch err := err.(type) {
		case nil:
			return encodeResponse(h.ID, certChain)
		case gokeyless.Error:
			log.Println(err)

			return encodeError(h.ID, err)
		default:
			log.Println(err)

			return encodeError(h.ID, gokeyless.ErrInternal)
		}
	case gokeyless.OpRSADecrypt, OpRSADecryptRaw:
		if key, ok = s.keys.Get(h.Body); !ok {
			log.Println(gokeyless.ErrKeyNotFound)

			return encodeError(h.ID, gokeyless.ErrKeyNotFound)
		}

		if _, ok = key.Public().(*rsa.PublicKey); !ok {
			log.Printf("%s: Key is not RSA\n", gokeyless.ErrCrypto)

			return encodeError(h.ID, gokeyless.ErrCrypto)
		}

		var ptxt []byte

		if h.Body.Opcode == OpRSADecryptRaw {
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				log.Printf("%s: Key is not rsa.PrivateKey\n", gokeyless.ErrCrypto)

				return encodeError(h.ID, gokeyless.ErrCrypto)
			}

			ptxt, err = rsaRawDecrypt(rand.Reader, rsaKey, h.Body.Payload)
		} else {
			rsaKey, ok := key.(crypto.Decrypter)
			if !ok {
				log.Printf("%s: Key is not Decrypter\n", gokeyless.ErrCrypto)

				return encodeError(h.ID, gokeyless.ErrCrypto)
			}

			ptxt, err = rsaKey.Decrypt(rand.Reader, h.Body.Payload, nil)
		}

		if err != nil {
			log.Printf("%s: Decryption error: %v", gokeyless.ErrCrypto, err)

			return encodeError(h.ID, gokeyless.ErrCrypto)
		}

		return encodeResponse(h.ID, ptxt)
	case gokeyless.OpRSASignMD5SHA1, gokeyless.OpECDSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case gokeyless.OpRSASignSHA1, gokeyless.OpECDSASignSHA1:
		opts = crypto.SHA1
	case gokeyless.OpRSASignSHA224, gokeyless.OpECDSASignSHA224:
		opts = crypto.SHA224
	case gokeyless.OpRSASignSHA256, gokeyless.OpECDSASignSHA256:
		opts = crypto.SHA256
	case gokeyless.OpRSASignSHA384, gokeyless.OpECDSASignSHA384:
		opts = crypto.SHA384
	case gokeyless.OpRSASignSHA512, gokeyless.OpECDSASignSHA512:
		opts = crypto.SHA512
	//case gokeyless.OpActivate:
	case gokeyless.OpPong, gokeyless.OpResponse, gokeyless.OpError:
		log.Printf("%s: %s is not a valid request Opcode\n", gokeyless.ErrUnexpectedOpcode, h.Body.Opcode)

		return encodeError(h.ID, gokeyless.ErrUnexpectedOpcode)
	default:
		return encodeError(h.ID, gokeyless.ErrBadOpcode)
	}

	if key, ok = s.keys.Get(h.Body); !ok {
		log.Println(gokeyless.ErrKeyNotFound)

		return encodeError(h.ID, gokeyless.ErrKeyNotFound)
	}

	// Ensure we don't perform an ECDSA sign for an RSA request.
	switch h.Body.Opcode {
	case gokeyless.OpRSASignMD5SHA1,
		gokeyless.OpRSASignSHA1,
		gokeyless.OpRSASignSHA224,
		gokeyless.OpRSASignSHA256,
		gokeyless.OpRSASignSHA384,
		gokeyless.OpRSASignSHA512:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			log.Printf("%s: request is RSA, but key isn't\n", gokeyless.ErrCrypto)

			return encodeError(h.ID, gokeyless.ErrCrypto)
		}
	}

	sig, err := key.Sign(rand.Reader, h.Body.Payload, opts)
	if err != nil {
		log.Printf("%s: Signing error: %v\n", gokeyless.ErrCrypto, err)

		return encodeError(h.ID, gokeyless.ErrCrypto)
	}

	return encodeResponse(h.ID, sig)
}
