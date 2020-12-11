package zkgroup

/*
#cgo LDFLAGS: ${SRCDIR}/lib/libzkgroup.a
#include "./lib/zkgroup.h"
*/
import "C"

// GroupSecretParams ...
type GroupSecretParams []byte

// GroupPublicParams ...
type GroupPublicParams []byte

// GenerateGroupSecretParams ...
func GenerateGroupSecretParams() (GroupSecretParams, error) {
	return GenerateGroupSecretParamsDeterministic(randBytes(32))
}

// GenerateGroupSecretParamsDeterministic ...
func GenerateGroupSecretParamsDeterministic(random []byte) (GroupSecretParams, error) {
	out := make([]byte, C.GROUP_SECRET_PARAMS_LEN)
	if res := C.FFI_GroupSecretParams_generateDeterministic(cBytes(random), cLen(random), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return GroupSecretParams(out), nil
}

// NewGroupSecretParams ...
func NewGroupSecretParams(masterKey []byte) (GroupSecretParams, error) {
	out := make([]byte, C.GROUP_SECRET_PARAMS_LEN)
	if res := C.FFI_GroupSecretParams_deriveFromMasterKey(cBytes(masterKey), cLen(masterKey), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return GroupSecretParams(out), nil
}

// MasterKey ...
func (g GroupSecretParams) MasterKey() ([]byte, error) {
	out := make([]byte, 32)
	if res := C.FFI_GroupSecretParams_getMasterKey(cBytes(g), cLen(g), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return out, nil
}

// PublicParams ...
func (g GroupSecretParams) PublicParams() (GroupPublicParams, error) {
	out := make([]byte, C.GROUP_PUBLIC_PARAMS_LEN)
	if res := C.FFI_GroupSecretParams_getPublicParams(cBytes(g), cLen(g), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return GroupPublicParams(out), nil
}
