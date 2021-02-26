package zkgroup

/*
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_arm64.so
#cgo linux,arm6 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_armhf.so
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_amd64.so
#include "./lib/zkgroup.h"
*/
import "C"
import "encoding/binary"

// AuthCredential ...
type AuthCredential []byte

// NewAuthCredential ...
func NewAuthCredential(b []byte) (AuthCredential, error) {
	if res := C.FFI_AuthCredential_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredential(b), nil
}

// AuthCredentialResponse ...
type AuthCredentialResponse []byte

// NewAuthCredentialResponse ...
func NewAuthCredentialResponse(b []byte) (AuthCredentialResponse, error) {
	if res := C.FFI_AuthCredentialResponse_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredentialResponse(b), nil
}

// AuthCredentialPresentation ...
type AuthCredentialPresentation []byte

// NewAuthCredentialPresentation ...
func NewAuthCredentialPresentation(b []byte) (AuthCredentialPresentation, error) {
	if res := C.FFI_AuthCredentialPresentation_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredentialPresentation(b), nil
}

// UUIDCiphertext ...
func (a AuthCredentialPresentation) UUIDCiphertext() ([]byte, error) {
	out := make([]byte, C.UUID_CIPHERTEXT_LEN)
	if res := C.FFI_AuthCredentialPresentation_getUuidCiphertext(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return out, nil
}

// RedemptionTime ...
func (a AuthCredentialPresentation) RedemptionTime() (uint32, error) {
	out := make([]byte, 4)
	if res := C.FFI_AuthCredentialPresentation_getRedemptionTime(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return 0, errFromCode(res)
	}
	return binary.BigEndian.Uint32(out), nil
}
