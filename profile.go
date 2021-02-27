package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_arm64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armhf

#include "lib/zkgroup.h"
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
