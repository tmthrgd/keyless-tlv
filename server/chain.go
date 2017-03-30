package server

import (
	"crypto"
	"crypto/cipher"

	"github.com/tmthrgd/keyless-tlv"
)

type GetCertChain []GetCertFunc

func (ch GetCertChain) GetCertificate(op *keyless.Operation) (cert *keyless.Certificate, err error) {
	for _, fn := range ch {
		if cert, err = fn(op); keyless.GetErrorCode(err) != keyless.ErrorCertNotFound {
			return
		}
	}

	return nil, keyless.ErrorCertNotFound
}

type GetKeyChain []GetKeyFunc

func (ch GetKeyChain) GetKey(ski keyless.SKI) (priv crypto.PrivateKey, err error) {
	for _, fn := range ch {
		if priv, err = fn(ski); keyless.GetErrorCode(err) != keyless.ErrorKeyNotFound {
			return
		}
	}

	return nil, keyless.ErrorKeyNotFound
}

type GetSealerChain []GetSealerFunc

func (ch GetSealerChain) GetSealer(op *keyless.Operation) (aead cipher.AEAD, err error) {
	for _, fn := range ch {
		if aead, err = fn(op); keyless.GetErrorCode(err) != keyless.ErrorKeyNotFound {
			return
		}
	}

	return nil, keyless.ErrorKeyNotFound
}
