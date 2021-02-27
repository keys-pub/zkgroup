package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_arm64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armhf

#include "lib/zkgroup.h"
*/
import "C"
import (
	"crypto/rand"
	"unsafe"
)

func cBytes(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func cLen(b []byte) C.uint32_t {
	return C.uint32_t(len(b))
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
