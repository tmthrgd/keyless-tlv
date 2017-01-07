package keyless

import (
	"crypto"

	"golang.org/x/crypto/ed25519"
)

type GetCertChain []GetCertFunc

func (ch GetCertChain) GetCertificate(op *Operation) (cert *Certificate, err error) {
	for _, fn := range ch {
		if cert, err = fn(op); getErrorCode(err) != ErrorCertNotFound {
			return
		}
	}

	return nil, ErrorCertNotFound
}

type GetKeyChain []GetKeyFunc

func (ch GetKeyChain) GetKey(ski SKI) (priv crypto.PrivateKey, err error) {
	for _, fn := range ch {
		if priv, err = fn(ski); getErrorCode(err) != ErrorKeyNotFound {
			return
		}
	}

	return nil, ErrorKeyNotFound
}

type AnyIsAuthorised []IsAuthorisedFunc

func (any AnyIsAuthorised) IsAuthorised(pub ed25519.PublicKey, op *Operation) error {
	for _, fn := range any {
		if err := fn(pub, op); getErrorCode(err) != ErrorNotAuthorised {
			return err
		}
	}

	return nil
}

type AllIsAuthorised []IsAuthorisedFunc

func (all AllIsAuthorised) IsAuthorised(pub ed25519.PublicKey, op *Operation) error {
	for _, fn := range all {
		if err := fn(pub, op); err != nil {
			return err
		}
	}

	return nil
}
