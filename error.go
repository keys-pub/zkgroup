package zkgroup

/*
#cgo LDFLAGS: ${SRCDIR}/lib/libzkgroup.a
#include "./lib/zkgroup.h"
*/
import "C"
import (
	"errors"
	"fmt"
)

// ErrVerificationFailed if verification failed.
var ErrVerificationFailed = errors.New("verification failed")

// ErrInternal if internal error.
var ErrInternal = errors.New("internal error")

// ErrInvalidInput if invalid input.
var ErrInvalidInput = errors.New("invalid input")

// Error is a generic error with code.
type Error struct {
	Code int
}

func errFromCode(code C.int) error {
	switch code {
	case C.FFI_RETURN_OK:
		return nil
	case C.FFI_RETURN_INTERNAL_ERROR:
		return ErrInternal
	case C.FFI_RETURN_INPUT_ERROR:
		return ErrInvalidInput
	default:
		return Error{Code: int(code)}
	}
}

func (e Error) Error() string {
	return fmt.Sprintf("zkgroup error %d", e.Code)
}