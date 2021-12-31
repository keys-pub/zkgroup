package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_x86_64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_aarch64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armv7

#include "lib/zkgroup.h"
*/
import "C"

const (
	profileKeyCommitmentSize = 97
	profileKeyVersionSize    = 64
)

func ProfileKeyGetCommitment(profileKey []byte, uuid []byte) (ProfileKeyCommitment, error) {
	out := make([]byte, profileKeyCommitmentSize)
	if res := C.FFI_ProfileKey_getCommitment(cBytes(profileKey), cLen(profileKey), cBytes(uuid), cLen(uuid), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCommitment(out), nil
}

type ProfileKeyVersion []byte

// ProfileKeyGetProfileKeyVersion returns the profile key version
func ProfileKeyGetProfileKeyVersion(profileKey []byte, uuid []byte) (ProfileKeyVersion, error) {
	out := make([]byte, profileKeyVersionSize)
	if res := C.FFI_ProfileKey_getProfileKeyVersion(cBytes(profileKey), cLen(profileKey), cBytes(uuid), cLen(uuid), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyVersion(out), nil
}

// ProfileKeyCredentialPresentation ...
type ProfileKeyCredentialPresentation []byte

// NewAuthCredentialPresentation ...

func NewProfileKeyCredentialPresentation(b []byte) (ProfileKeyCredentialPresentation, error) {
	if res := C.FFI_ProfileKeyCredentialPresentation_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialPresentation(b), nil
}

// UUIDCiphertext ...
func (a ProfileKeyCredentialPresentation) UUIDCiphertext() ([]byte, error) {
	out := make([]byte, C.UUID_CIPHERTEXT_LEN)
	if res := C.FFI_ProfileKeyCredentialPresentation_getUuidCiphertext(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return out, nil
}

// ProfileKeyCiphertext ...
func (a ProfileKeyCredentialPresentation) ProfileKeyCiphertext() ([]byte, error) {
	out := make([]byte, C.PROFILE_KEY_CIPHERTEXT_LEN)
	if res := C.FFI_ProfileKeyCredentialPresentation_getProfileKeyCiphertext(cBytes(a), cLen(a), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return out, nil
}

// ProfileKeyCredentialResponse ...
type ProfileKeyCredentialResponse []byte

// NewProfileKeyCredentialResponse ...
func NewProfileKeyCredentialResponse(b []byte) (ProfileKeyCredentialResponse, error) {
	if res := C.FFI_ProfileKeyCredentialResponse_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialResponse(b), nil
}

type ProfileKeyCredentialRequestContext []byte

func CreateProfileKeyCredentialRequestContext(serverPublicParams, uuid, profileKey []byte) (ProfileKeyCredentialRequestContext, error) {
	out := make([]byte, C.PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN)
	random := randBytes(32)
	if res := C.FFI_ServerPublicParams_createProfileKeyCredentialRequestContextDeterministic(
		cBytes(serverPublicParams), cLen(serverPublicParams),
		cBytes(random), cLen(random),
		cBytes(uuid), cLen(uuid),
		cBytes(profileKey), cLen(profileKey),
		cBytes(out), cLen(out),
	); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialRequestContext(out), nil

}
func (p *ProfileKeyCredentialRequestContext) ProfileKeyCredentialRequestContextGetRequest() (ProfileKeyCredentialRequest, error) {
	out := make([]byte, C.PROFILE_KEY_CREDENTIAL_REQUEST_LEN)
	q := *p

	if res := C.FFI_ProfileKeyCredentialRequestContext_getRequest(cBytes(q), cLen(q), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialRequest(out), nil
}
