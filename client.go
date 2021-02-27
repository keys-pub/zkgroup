package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_arm64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armhf

#include "lib/zkgroup.h"
*/
import "C"
import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// ClientZkGroupCipher ...
type ClientZkGroupCipher struct {
	groupSecretParams GroupSecretParams
}

// NewClientZkGroupCipher ...
func NewClientZkGroupCipher(groupSecretParams GroupSecretParams) *ClientZkGroupCipher {
	return &ClientZkGroupCipher{groupSecretParams: groupSecretParams}
}

// EncryptBlob ...
func (c ClientZkGroupCipher) EncryptBlob(plaintext []byte) ([]byte, error) {
	rand := randBytes(32)
	return c.EncryptBlobDeterministic(rand, plaintext)
}

// EncryptBlobDeterministic ...
func (c ClientZkGroupCipher) EncryptBlobDeterministic(random []byte, plaintext []byte) ([]byte, error) {
	paddedPlaintext := append([]byte{0x00, 0x00, 0x00, 0x00}, plaintext...)
	ciphertext := make([]byte, len(paddedPlaintext)+29)
	if res := C.FFI_GroupSecretParams_encryptBlobDeterministic(cBytes(c.groupSecretParams), cLen(c.groupSecretParams), cBytes(random), cLen(random), cBytes(paddedPlaintext), cLen(paddedPlaintext), cBytes(ciphertext), cLen(ciphertext)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ciphertext, nil
}

// DecryptBlob ...
func (c ClientZkGroupCipher) DecryptBlob(ciphertext []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext)-29)
	if res := C.FFI_GroupSecretParams_decryptBlob(cBytes(c.groupSecretParams), cLen(c.groupSecretParams), cBytes(ciphertext), cLen(ciphertext), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	if len(out) < 4 {
		return nil, ErrVerificationFailed
	}

	padLenBytes := out[0:4]
	padLen := int(binary.BigEndian.Uint32(padLenBytes))

	if len(out) < (4 + padLen) {
		return nil, ErrVerificationFailed
	}

	return out[4 : len(out)-padLen], nil
}

// EncryptUUID ...
func (c ClientZkGroupCipher) EncryptUUID(uuid UUID) ([]byte, error) {
	if len(uuid) != C.UUID_LEN {
		return nil, errors.Errorf("invalid uuid length", len(uuid), C.UUID_LEN)
	}
	ciphertext := make([]byte, C.UUID_CIPHERTEXT_LEN)
	if res := C.FFI_GroupSecretParams_encryptUuid(cBytes(c.groupSecretParams), cLen(c.groupSecretParams), cBytes(uuid), cLen(uuid), cBytes(ciphertext), cLen(ciphertext)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ciphertext, nil
}

// DecryptUUID ...
func (c ClientZkGroupCipher) DecryptUUID(ciphertext []byte) (UUID, error) {
	uuid := make([]byte, C.UUID_LEN)
	if res := C.FFI_GroupSecretParams_decryptUuid(cBytes(c.groupSecretParams), cLen(c.groupSecretParams), cBytes(ciphertext), cLen(ciphertext), cBytes(uuid), cLen(uuid)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return uuid, nil
}

// ClientZkAuthOperations ...
type ClientZkAuthOperations struct {
	serverPublicParams ServerPublicParams
}

// NewClientZkAuthOperations ...
func NewClientZkAuthOperations(serverPublicParams ServerPublicParams) (*ClientZkAuthOperations, error) {
	if serverPublicParams == nil {
		return nil, errors.Errorf("empty server public params")
	}
	return &ClientZkAuthOperations{serverPublicParams: serverPublicParams}, nil
}

// ReceiveAuthCredential ...
func (c ClientZkAuthOperations) ReceiveAuthCredential(uuid UUID, redemptionTime uint32, authCredentialResponse AuthCredentialResponse) (AuthCredential, error) {
	out := make([]byte, C.AUTH_CREDENTIAL_LEN)
	if res := C.FFI_ServerPublicParams_receiveAuthCredential(
		cBytes(c.serverPublicParams), cLen(c.serverPublicParams),
		cBytes(uuid), cLen(uuid),
		C.uint32_t(redemptionTime),
		cBytes(authCredentialResponse), cLen(authCredentialResponse),
		cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredential(out), nil
}

// CreateAuthCredentialPresentation ...
func (c ClientZkAuthOperations) CreateAuthCredentialPresentation(groupSecretParams GroupSecretParams, authCredential AuthCredential) (AuthCredentialPresentation, error) {
	return c.CreateAuthCredentialPresentationDeterministic(randBytes(32), groupSecretParams, authCredential)
}

// CreateAuthCredentialPresentationDeterministic ...
func (c ClientZkAuthOperations) CreateAuthCredentialPresentationDeterministic(random []byte, groupSecretParams GroupSecretParams, authCredential AuthCredential) (AuthCredentialPresentation, error) {
	out := make([]byte, C.AUTH_CREDENTIAL_PRESENTATION_LEN)
	if res := C.FFI_ServerPublicParams_createAuthCredentialPresentationDeterministic(
		cBytes(c.serverPublicParams), cLen(c.serverPublicParams),
		cBytes(random), cLen(random),
		cBytes(groupSecretParams), cLen(groupSecretParams),
		cBytes(authCredential), cLen(authCredential),
		cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredentialPresentation(out), nil
}
