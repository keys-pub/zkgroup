package zkgroup

/*
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_arm64.so
#cgo linux,arm6 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_armhf.so
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/libzkgroup_linux_amd64.so
#include "./lib/zkgroup.h"
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
