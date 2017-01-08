package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"golang.org/x/crypto/ed25519"

	"github.com/tmthrgd/keyless"
)

type RSARawDecryptOptions struct{}

var (
	rsaRawDecryptOpts = new(RSARawDecryptOptions)

	rsaPSSOptsSHA256 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA256}
	rsaPSSOptsSHA384 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA384}
	rsaPSSOptsSHA512 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA512}
)

func (h *RequestHandler) Process(in *keyless.Operation) (out *keyless.Operation, err error) {
	out = new(keyless.Operation)

	var signOpts crypto.SignerOpts
	var decryptOpts crypto.DecrypterOpts

	switch in.Opcode {
	case keyless.OpPing:
		out.Opcode = keyless.OpPong

		if in.Payload == nil {
			out.Payload = make([]byte, 0)
		} else {
			out.Payload = in.Payload
		}

		return
	case keyless.OpGetCertificate:
		if h.GetCert == nil {
			err = keyless.ErrorCertNotFound
			return
		}

		var cert *keyless.Certificate
		if cert, err = h.GetCert(in); err == nil {
			out.SKI, out.Payload, out.OCSPResponse = cert.SKI, cert.Payload, cert.OCSP
		}

		return
	case keyless.OpRSADecrypt:
	case keyless.OpRSADecryptRaw:
		decryptOpts = rsaRawDecryptOpts
	case keyless.OpRSASignMD5SHA1, keyless.OpECDSASignMD5SHA1:
		signOpts = crypto.MD5SHA1
	case keyless.OpRSASignSHA1, keyless.OpECDSASignSHA1:
		signOpts = crypto.SHA1
	case keyless.OpRSASignSHA224, keyless.OpECDSASignSHA224:
		signOpts = crypto.SHA224
	case keyless.OpRSASignSHA256, keyless.OpECDSASignSHA256:
		signOpts = crypto.SHA256
	case keyless.OpRSASignSHA384, keyless.OpECDSASignSHA384:
		signOpts = crypto.SHA384
	case keyless.OpRSASignSHA512, keyless.OpECDSASignSHA512:
		signOpts = crypto.SHA512
	case keyless.OpRSAPSSSignSHA256:
		signOpts = rsaPSSOptsSHA256
	case keyless.OpRSAPSSSignSHA384:
		signOpts = rsaPSSOptsSHA384
	case keyless.OpRSAPSSSignSHA512:
		signOpts = rsaPSSOptsSHA512
	case keyless.OpEd25519Sign:
		signOpts = crypto.Hash(0)
	case keyless.OpPong, keyless.OpResponse, keyless.OpError:
		err = keyless.WrappedError{keyless.ErrorUnexpectedOpcode, errors.New(in.Opcode.String())}
		return
	case keyless.OpActivate:
		fallthrough
	default:
		err = keyless.WrappedError{keyless.ErrorBadOpcode, errors.New(in.Opcode.String())}
		return
	}

	if h.GetKey == nil || !in.SKI.Valid() {
		err = keyless.ErrorKeyNotFound
		return
	}

	key, err := h.GetKey(in.SKI)
	if err != nil {
		return
	}

	type publicKeyMethod interface {
		Public() crypto.PublicKey
	}

	publicInt, ok := key.(publicKeyMethod)
	if !ok {
		err = keyless.WrappedError{keyless.ErrorCryptoFailed,
			errors.New("key does not implemented crypto.Decrypter or crypto.Signer")}
		return
	}

	// Ensure we don't perform a sign operation for a key type that differs from the request.
	switch in.Opcode {
	case keyless.OpRSADecrypt, keyless.OpRSADecryptRaw,
		keyless.OpRSASignMD5SHA1, keyless.OpRSASignSHA1, keyless.OpRSASignSHA224,
		keyless.OpRSASignSHA256, keyless.OpRSASignSHA384, keyless.OpRSASignSHA512,
		keyless.OpRSAPSSSignSHA256, keyless.OpRSAPSSSignSHA384, keyless.OpRSAPSSSignSHA512:
		if _, ok := publicInt.Public().(*rsa.PublicKey); !ok {
			err = keyless.WrappedError{keyless.ErrorCryptoFailed,
				errors.New("request is RSA, but key is not")}
			return
		}
	case keyless.OpECDSASignMD5SHA1, keyless.OpECDSASignSHA1, keyless.OpECDSASignSHA224,
		keyless.OpECDSASignSHA256, keyless.OpECDSASignSHA384, keyless.OpECDSASignSHA512:
		if _, ok := publicInt.Public().(*ecdsa.PublicKey); !ok {
			err = keyless.WrappedError{keyless.ErrorCryptoFailed,
				errors.New("request is ECDSA, but key is not")}
			return
		}
	case keyless.OpEd25519Sign:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			if _, ok = publicInt.Public().(ed25519.PublicKey); !ok {
				err = keyless.WrappedError{keyless.ErrorCryptoFailed,
					errors.New("request is EdDSA, but key is not")}
				return
			}
		}
	default:
		panic("unreachable")
	}

	switch in.Opcode {
	case keyless.OpRSADecryptRaw:
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			out.Payload, err = rsaRawDecrypt(rand.Reader, rsaKey, in.Payload)
			break
		}

		fallthrough
	case keyless.OpRSADecrypt:
		if decrypter, ok := key.(crypto.Decrypter); ok {
			out.Payload, err = decrypter.Decrypt(rand.Reader, in.Payload, decryptOpts)
		} else {
			err = errors.New("key does not implemented crypto.Decrypter")
		}
	default:
		if signer, ok := key.(crypto.Signer); ok {
			out.Payload, err = signer.Sign(rand.Reader, in.Payload, signOpts)
		} else {
			err = errors.New("key does not implemented crypto.Signer")
		}
	}

	if err != nil {
		err = keyless.WrappedError{keyless.ErrorCryptoFailed, err}
	}

	return
}
