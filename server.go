package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_arm64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armhf

#include "lib/zkgroup.h"
*/
import "C"

// NotarySignature ... has a may length of 64
type NotarySignature []byte

// ServerPublicParams ...
type ServerPublicParams []byte

// NewServerPublicParams ...
func NewServerPublicParams(b []byte) (ServerPublicParams, error) {
	if res := C.FFI_ServerPublicParams_checkValidContents(cBytes(b), cLen(b)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ServerPublicParams(b), nil
}

// VerifySignature ...
func (p ServerPublicParams) VerifySignature(message []byte, notarySignarture NotarySignature) error {

	if res := C.FFI_ServerPublicParams_verifySignature(cBytes(p), cLen(p), cBytes(message), cLen(message), cBytes(notarySignarture), cLen(notarySignarture)); res != C.FFI_RETURN_OK {
		if res == C.FFI_RETURN_INPUT_ERROR {
			return ErrVerificationFailed
		}
		return errFromCode(res)
	}
	return nil
}

// ServerSecretParams ...
type ServerSecretParams []byte

// GenerateServerSecretParams ...
func GenerateServerSecretParams() (ServerSecretParams, error) {
	return GenerateServerSecretParamsDeterministic(randBytes(32))
}

// GenerateServerSecretParamsDeterministic ...
func GenerateServerSecretParamsDeterministic(random []byte) (ServerSecretParams, error) {
	out := make([]byte, C.SERVER_SECRET_PARAMS_LEN)
	if res := C.FFI_ServerSecretParams_generateDeterministic(cBytes(random), cLen(random), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ServerSecretParams(out), nil
}

// PublicParams ...
func (g ServerSecretParams) PublicParams() (ServerPublicParams, error) {
	out := make([]byte, C.SERVER_PUBLIC_PARAMS_LEN)
	if res := C.FFI_ServerSecretParams_getPublicParams(cBytes(g), cLen(g), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ServerPublicParams(out), nil
}

// Sign ...
func (g ServerSecretParams) Sign(message []byte) (NotarySignature, error) {
	return g.SignDeterministic(randBytes(32), message)
}

// SignDeterministic ...
func (g ServerSecretParams) SignDeterministic(rand []byte, message []byte) (NotarySignature, error) {
	out := make([]byte, C.SIGNATURE_LEN)
	if res := C.FFI_ServerSecretParams_signDeterministic(cBytes(g), cLen(g), cBytes(rand), cLen(rand), cBytes(message), cLen(message), cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return out, nil
}

// ServerZkAuthOperations ...
type ServerZkAuthOperations struct {
	serverSecretParams ServerSecretParams
}

// NewServerZkAuthOperations ...
func NewServerZkAuthOperations(serverSecretParams ServerSecretParams) *ServerZkAuthOperations {
	return &ServerZkAuthOperations{serverSecretParams: serverSecretParams}
}

// IssueAuthCredential ...
func (c ServerZkAuthOperations) IssueAuthCredential(uuid UUID, redemptionTime uint32) (AuthCredentialResponse, error) {
	return c.IssueAuthCredentialDeterministic(randBytes(32), uuid, redemptionTime)
}

// IssueAuthCredentialDeterministic ...
func (c ServerZkAuthOperations) IssueAuthCredentialDeterministic(random []byte, uuid UUID, redemptionTime uint32) (AuthCredentialResponse, error) {
	out := make([]byte, C.AUTH_CREDENTIAL_RESPONSE_LEN)
	if res := C.FFI_ServerSecretParams_issueAuthCredentialDeterministic(
		cBytes(c.serverSecretParams), cLen(c.serverSecretParams),
		cBytes(random), cLen(random),
		cBytes(uuid), cLen(uuid),
		C.uint32_t(redemptionTime),
		cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return AuthCredentialResponse(out), nil
}

// VerifyAuthCredentialPresentation ...
func (c ServerZkAuthOperations) VerifyAuthCredentialPresentation(groupPublicParams GroupPublicParams, authCredentialPresentation AuthCredentialPresentation) error {
	if res := C.FFI_ServerSecretParams_verifyAuthCredentialPresentation(
		cBytes(c.serverSecretParams), cLen(c.serverSecretParams),
		cBytes(groupPublicParams), cLen(groupPublicParams),
		cBytes(authCredentialPresentation), cLen(authCredentialPresentation)); res != C.FFI_RETURN_OK {
		if res == C.FFI_RETURN_INPUT_ERROR {
			return ErrVerificationFailed
		}
		return errFromCode(res)
	}
	return nil
}
