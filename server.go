package zkgroup

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_x86_64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_aarch64
#cgo linux,arm LDFLAGS: -L${SRCDIR}/lib '-Wl,-rpath,$$ORIGIN/' -lzkgroup_linux_armv7

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

type ProfileKeyCredential []byte

func (p ServerPublicParams) ReceiveProfileKeyCredential(profileKeyCredentialRequestContext, profileKeyCredentialResponse []byte) (ProfileKeyCredential, error) {
	out := make([]byte, C.PROFILE_KEY_CREDENTIAL_LEN)
	if res := C.FFI_ServerPublicParams_receiveProfileKeyCredential(
		cBytes(p), cLen(p),
		cBytes(profileKeyCredentialRequestContext), cLen(profileKeyCredentialRequestContext),
		cBytes(profileKeyCredentialResponse), cLen(profileKeyCredentialResponse),
		cBytes(out), cLen(out),
	); res != C.FFI_RETURN_OK {
		if res == C.FFI_RETURN_INPUT_ERROR {
			return nil, ErrVerificationFailed
		}
		return nil, errFromCode(res)
	}
	return ProfileKeyCredential(out), nil
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

// ServerZkProfileOperations ...
type ServerZkProfileOperations struct {
	serverSecretParams ServerSecretParams
}

// NewServerZkProfileOperations ...
func NewServerZkProfileOperations(serverSecretParams ServerSecretParams) *ServerZkProfileOperations {
	return &ServerZkProfileOperations{serverSecretParams: serverSecretParams}
}

type ProfileKeyCredentialRequest []byte
type ProfileKeyCommitment []byte

// IssueAuthCredential ...
func (c ServerZkProfileOperations) IssueProfileKeyCredential(profileKeyCredentialRequest ProfileKeyCredentialRequest, uuid UUID, profileKeyCommitment ProfileKeyCommitment) (ProfileKeyCredentialResponse, error) {
	return c.IssueProfileKeyCredentialDeterministic(randBytes(32), profileKeyCredentialRequest, uuid, profileKeyCommitment)
}

// IssueAuthCredentialDeterministic ...
func (c ServerZkProfileOperations) IssueProfileKeyCredentialDeterministic(random []byte,
	profileKeyCredentialRequest ProfileKeyCredentialRequest,
	uuid UUID,
	profileKeyCommitment ProfileKeyCommitment,

) (ProfileKeyCredentialResponse, error) {
	out := make([]byte, C.PROFILE_KEY_CREDENTIAL_RESPONSE_LEN)
	if res := C.FFI_ServerSecretParams_issueProfileKeyCredentialDeterministic(
		cBytes(c.serverSecretParams), cLen(c.serverSecretParams),
		cBytes(random), cLen(random),
		cBytes(profileKeyCredentialRequest), cLen(profileKeyCredentialRequest),
		cBytes(uuid), cLen(uuid),
		cBytes(profileKeyCommitment), cLen(profileKeyCommitment),
		cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialResponse(out), nil
}

// VerifyProfileKeyCredentialPresentation ...
func (c ServerZkProfileOperations) VerifyProfileKeyCredentialPresentation(groupPublicParams GroupPublicParams, profileKeyCredentialPresentation ProfileKeyCredentialPresentation) error {
	if res := C.FFI_ServerSecretParams_verifyProfileKeyCredentialPresentation(
		cBytes(c.serverSecretParams), cLen(c.serverSecretParams),
		cBytes(groupPublicParams), cLen(groupPublicParams),
		cBytes(profileKeyCredentialPresentation), cLen(profileKeyCredentialPresentation)); res != C.FFI_RETURN_OK {
		if res == C.FFI_RETURN_INPUT_ERROR {
			return ErrVerificationFailed
		}
		return errFromCode(res)
	}
	return nil
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
func (s ServerPublicParams) CreateProfileKeyCredentialPresentation(groupSecretParams, profileKeyCredential []byte) ([]byte, error) {
	out := make([]byte, C.PROFILE_KEY_CREDENTIAL_PRESENTATION_LEN)
	random := randBytes(32)
	if res := C.FFI_ServerPublicParams_createProfileKeyCredentialPresentationDeterministic(
		cBytes(s), cLen(s),
		cBytes(random), cLen(random),
		cBytes(groupSecretParams), cLen(groupSecretParams),
		cBytes(profileKeyCredential), cLen(profileKeyCredential),
		cBytes(out), cLen(out)); res != C.FFI_RETURN_OK {
		return nil, errFromCode(res)
	}
	return ProfileKeyCredentialPresentation(out), nil
}
