package zkgroup

/*
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_arm64.so
#cgo linux,arm6 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_armhf.so
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_amd64.so
#include "./lib/zkgroup.h"
*/
import "C"

const (
	profileKeyCommitmentSize = 97
	profileKeyVersionSize    = 64
)

func ProfileKeyGetCommitment(profileKey []byte, uuid []byte) (ServerSecretParams, error) {
	out := make([]byte, profileKeyCommitmentSize)
	if res := C.FFI_ProfileKey_getCommitment(cBytes(profileKey), cLen(profileKey), cBytes(uuid), cLen(uuid), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ServerSecretParams(out), nil
}

// ProfileKeyGetProfileKeyVersion returns the profile key version
func ProfileKeyGetProfileKeyVersion(profileKey []byte, uuid []byte) (ServerSecretParams, error) {
	out := make([]byte, profileKeyVersionSize)
	if res := C.FFI_ProfileKey_getProfileKeyVersion(cBytes(profileKey), cLen(profileKey), cBytes(uuid), cLen(uuid), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ServerSecretParams(out), nil
}
