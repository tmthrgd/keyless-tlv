package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"golang.org/x/crypto/ed25519"
)

type RSARawDecryptOptions struct{}

var (
	rsaRawDecryptOpts = new(RSARawDecryptOptions)

	rsaPSSOptsSHA256 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA256}
	rsaPSSOptsSHA384 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA384}
	rsaPSSOptsSHA512 = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA512}
)

func (h *RequestHandler) Process(in *Operation) (out *Operation, err error) {
	out = new(Operation)

	var signOpts crypto.SignerOpts
	var decryptOpts crypto.DecrypterOpts

	switch in.Opcode {
	case OpPing:
		out.Opcode = OpPong

		if in.Payload == nil {
			out.Payload = make([]byte, 0)
		} else {
			out.Payload = in.Payload
		}

		return
	case OpGetCertificate:
		if h.GetCert == nil {
			err = ErrorCertNotFound
			return
		}

		var cert *Certificate
		if cert, err = h.GetCert(in); err == nil {
			out.SKI, out.Payload, out.OCSPResponse = cert.SKI, cert.Payload, cert.OCSP
		}

		return
	case OpRSADecrypt:
	case OpRSADecryptRaw:
		decryptOpts = rsaRawDecryptOpts
	case OpRSASignMD5SHA1, OpECDSASignMD5SHA1:
		signOpts = crypto.MD5SHA1
	case OpRSASignSHA1, OpECDSASignSHA1:
		signOpts = crypto.SHA1
	case OpRSASignSHA224, OpECDSASignSHA224:
		signOpts = crypto.SHA224
	case OpRSASignSHA256, OpECDSASignSHA256:
		signOpts = crypto.SHA256
	case OpRSASignSHA384, OpECDSASignSHA384:
		signOpts = crypto.SHA384
	case OpRSASignSHA512, OpECDSASignSHA512:
		signOpts = crypto.SHA512
	case OpRSAPSSSignSHA256:
		signOpts = rsaPSSOptsSHA256
	case OpRSAPSSSignSHA384:
		signOpts = rsaPSSOptsSHA384
	case OpRSAPSSSignSHA512:
		signOpts = rsaPSSOptsSHA512
	case OpEd25519Sign:
		signOpts = crypto.Hash(0)
	case OpPong, OpResponse, OpError:
		err = WrappedError{ErrorUnexpectedOpcode, errors.New(in.Opcode.String())}
		return
	case OpActivate:
		fallthrough
	default:
		err = WrappedError{ErrorBadOpcode, errors.New(in.Opcode.String())}
		return
	}

	if h.GetKey == nil || !in.SKI.Valid() {
		err = ErrorKeyNotFound
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
		err = WrappedError{ErrorCryptoFailed, errors.New("key does not implemented crypto.Decrypter or crypto.Signer")}
		return
	}

	// Ensure we don't perform a sign operation for a key type that differs from the request.
	switch in.Opcode {
	case OpRSADecrypt, OpRSADecryptRaw,
		OpRSASignMD5SHA1, OpRSASignSHA1, OpRSASignSHA224, OpRSASignSHA256, OpRSASignSHA384, OpRSASignSHA512,
		OpRSAPSSSignSHA256, OpRSAPSSSignSHA384, OpRSAPSSSignSHA512:
		if _, ok := publicInt.Public().(*rsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is RSA, but key is not")}
			return
		}
	case OpECDSASignMD5SHA1, OpECDSASignSHA1, OpECDSASignSHA224, OpECDSASignSHA256, OpECDSASignSHA384, OpECDSASignSHA512:
		if _, ok := publicInt.Public().(*ecdsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is ECDSA, but key is not")}
			return
		}
	case OpEd25519Sign:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			if _, ok = publicInt.Public().(ed25519.PublicKey); !ok {
				err = WrappedError{ErrorCryptoFailed, errors.New("request is EdDSA, but key is not")}
				return
			}
		}
	default:
		panic("unreachable")
	}

	switch in.Opcode {
	case OpRSADecryptRaw:
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			out.Payload, err = rsaRawDecrypt(rand.Reader, rsaKey, in.Payload)
			err = wrapError(ErrorCryptoFailed, err)
			return
		}

		fallthrough
	case OpRSADecrypt:
		if decrypter, ok := key.(crypto.Decrypter); ok {
			out.Payload, err = decrypter.Decrypt(rand.Reader, in.Payload, decryptOpts)
			err = wrapError(ErrorCryptoFailed, err)
		} else {
			err = WrappedError{ErrorCryptoFailed, errors.New("key does not implemented crypto.Decrypter")}
		}
	default:
		if signer, ok := key.(crypto.Signer); ok {
			out.Payload, err = signer.Sign(rand.Reader, in.Payload, signOpts)
			err = wrapError(ErrorCryptoFailed, err)
		} else {
			err = WrappedError{ErrorCryptoFailed, errors.New("key does not implemented crypto.Signer")}
		}
	}

	return
}
