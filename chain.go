package keyless

import "golang.org/x/crypto/ed25519"

type AnyIsAuthorised []IsAuthorisedFunc

func (any AnyIsAuthorised) IsAuthorised(pub ed25519.PublicKey, op *Operation) error {
	for _, fn := range any {
		if err := fn(pub, op); GetErrorCode(err) != ErrorNotAuthorised {
			return err
		}
	}

	return ErrorNotAuthorised
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
