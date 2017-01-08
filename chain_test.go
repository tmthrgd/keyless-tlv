package keyless

import (
	"testing"

	"golang.org/x/crypto/ed25519"
)

func isAuthorisedTrue(pub ed25519.PublicKey, op *Operation) error {
	return nil
}

func isAuthorisedFalse(pub ed25519.PublicKey, op *Operation) error {
	return ErrorNotAuthorised
}

func isAuthorisedError(pub ed25519.PublicKey, op *Operation) error {
	return ErrorInternal
}

func TestAnyIsAuthorised(t *testing.T) {
	any := AnyIsAuthorised{isAuthorisedFalse, isAuthorisedTrue, isAuthorisedError}
	if err := any.IsAuthorised(nil, nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	any = AnyIsAuthorised{isAuthorisedFalse, isAuthorisedFalse}
	if err := any.IsAuthorised(nil, nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}

	any = AnyIsAuthorised{isAuthorisedFalse, isAuthorisedError, isAuthorisedTrue}
	if err := any.IsAuthorised(nil, nil); err != ErrorInternal {
		t.Errorf("expected %v, got: %v", ErrorInternal, err)
	}

	any = AnyIsAuthorised{}
	if err := any.IsAuthorised(nil, nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}
}

func TestAllIsAuthorised(t *testing.T) {
	all := AllIsAuthorised{isAuthorisedTrue, isAuthorisedTrue}
	if err := all.IsAuthorised(nil, nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	all = AllIsAuthorised{isAuthorisedTrue, isAuthorisedFalse}
	if err := all.IsAuthorised(nil, nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}

	all = AllIsAuthorised{isAuthorisedError, isAuthorisedTrue, isAuthorisedFalse}
	if err := all.IsAuthorised(nil, nil); err != ErrorInternal {
		t.Errorf("expected %v, got: %v", ErrorInternal, err)
	}

	all = AllIsAuthorised{}
	if err := all.IsAuthorised(nil, nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}
