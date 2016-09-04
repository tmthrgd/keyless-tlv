package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

func processRequest(in Operation, getCert GetCertificate, getKey GetKey) (out Operation, err error) {
	var opts crypto.SignerOpts

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
		if getCert == nil {
			err = ErrorCertNotFound
			return
		}

		out.Payload, out.SKI, err = getCert(in)
		return
	case OpRSADecrypt, OpRSADecryptRaw:
		if getKey == nil {
			err = ErrorKeyNotFound
			return
		}

		var key crypto.Signer
		if key, err = getKey(in.SKI); err != nil {
			return
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is RSA, but key is not")}
			return
		}

		if in.Opcode == OpRSADecryptRaw {
			out.Payload, err = rsaRawDecrypt(rand.Reader, rsaKey, in.Payload)
		} else {
			out.Payload, err = rsaKey.Decrypt(rand.Reader, in.Payload, nil)
		}

		if err != nil {
			err = WrappedError{ErrorCryptoFailed, err}
		}

		return
	case OpRSASignMD5SHA1, OpECDSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case OpRSASignSHA1, OpECDSASignSHA1:
		opts = crypto.SHA1
	case OpRSASignSHA224, OpECDSASignSHA224:
		opts = crypto.SHA224
	case OpRSASignSHA256, OpECDSASignSHA256:
		opts = crypto.SHA256
	case OpRSASignSHA384, OpECDSASignSHA384:
		opts = crypto.SHA384
	case OpRSASignSHA512, OpECDSASignSHA512:
		opts = crypto.SHA512
	case OpRSAPSSSignSHA256:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA256}
	case OpRSAPSSSignSHA384:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA384}
	case OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, crypto.SHA512}
	case OpPong, OpResponse, OpError:
		err = WrappedError{ErrorUnexpectedOpcode, errors.New(in.Opcode.String())}
		return
	case OpActivate:
		fallthrough
	default:
		err = WrappedError{ErrorBadOpcode, errors.New(in.Opcode.String())}
		return
	}

	if getKey == nil {
		err = ErrorKeyNotFound
		return
	}

	var key crypto.Signer
	if key, err = getKey(in.SKI); err != nil {
		return
	}

	// Ensure we don't perform an ECDSA/RSA sign for an RSA/ECDSA request.
	switch in.Opcode {
	case OpRSASignMD5SHA1, OpRSASignSHA1, OpRSASignSHA224, OpRSASignSHA256, OpRSASignSHA384, OpRSASignSHA512,
		OpRSAPSSSignSHA256, OpRSAPSSSignSHA384, OpRSAPSSSignSHA512:
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is RSA, but key is not")}
			return
		}
	case OpECDSASignMD5SHA1, OpECDSASignSHA1, OpECDSASignSHA224, OpECDSASignSHA256, OpECDSASignSHA384, OpECDSASignSHA512:
		if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
			err = WrappedError{ErrorCryptoFailed, errors.New("request is ECDSA, but key is not")}
			return
		}
	}

	if out.Payload, err = key.Sign(rand.Reader, in.Payload, opts); err != nil {
		err = WrappedError{ErrorCryptoFailed, err}
	}

	return
}
