package keyless

import (
	"errors"
	"testing"
)

func TestGetErrorCode(t *testing.T) {
	for i := 0; i < 0x10000; i++ {
		if GetErrorCode(Error(i)) != Error(i) {
			t.Fatalf("GetErrorCode failed for error %v", Error(i))
		}
	}
}

func TestWrappedErrorMessage(t *testing.T) {
	e := WrappedError{ErrorInternal, errors.New("test")}
	if e.Error() != "internal error: test" {
		t.Fatalf("(WrappedError).Error failed, expected 'internal error: test', got '%s'", e.Error())
	}

	for i := 0; i < 0x10000; i++ {
		if GetErrorCode(WrappedError{Error(i), nil}) != Error(i) {
			t.Fatalf("GetErrorCode failed for error %v with WrappedError", Error(i))
		}
	}
}
