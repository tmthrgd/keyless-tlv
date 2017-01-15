package keyless

import "testing"

func isAuthorisedTrue(op *Operation) error {
	return nil
}

func isAuthorisedFalse(op *Operation) error {
	return ErrorNotAuthorised
}

func isAuthorisedError(op *Operation) error {
	return ErrorInternal
}

func TestAnyIsAuthorised(t *testing.T) {
	any := AnyIsAuthorised{isAuthorisedFalse, isAuthorisedTrue, isAuthorisedError}
	if err := any.IsAuthorised(nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	any = AnyIsAuthorised{isAuthorisedFalse, isAuthorisedFalse}
	if err := any.IsAuthorised(nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}

	any = AnyIsAuthorised{isAuthorisedFalse, isAuthorisedError, isAuthorisedTrue}
	if err := any.IsAuthorised(nil); err != ErrorInternal {
		t.Errorf("expected %v, got: %v", ErrorInternal, err)
	}

	any = AnyIsAuthorised{}
	if err := any.IsAuthorised(nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}
}

func TestAllIsAuthorised(t *testing.T) {
	all := AllIsAuthorised{isAuthorisedTrue, isAuthorisedTrue}
	if err := all.IsAuthorised(nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	all = AllIsAuthorised{isAuthorisedTrue, isAuthorisedFalse}
	if err := all.IsAuthorised(nil); err != ErrorNotAuthorised {
		t.Errorf("expected %v, got: %v", ErrorNotAuthorised, err)
	}

	all = AllIsAuthorised{isAuthorisedError, isAuthorisedTrue, isAuthorisedFalse}
	if err := all.IsAuthorised(nil); err != ErrorInternal {
		t.Errorf("expected %v, got: %v", ErrorInternal, err)
	}

	all = AllIsAuthorised{}
	if err := all.IsAuthorised(nil); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}
