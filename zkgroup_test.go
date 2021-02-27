package zkgroup_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/nanu-c/zkgroup"
	"github.com/stretchr/testify/require"
)

func TestAuthIntegration(t *testing.T) {
	uuid := zkgroup.UUID(test16)
	redemptionTime := uint32(123456)

	//
	// Server.
	//
	// Issue credential
	serverSecretParams, err := zkgroup.GenerateServerSecretParamsDeterministic(test32)
	require.NoError(t, err)
	serverPublicParams, err := serverSecretParams.PublicParams()
	require.NoError(t, err)

	serverZkAuth := zkgroup.NewServerZkAuthOperations(serverSecretParams)
	authCredentialResponse, err := serverZkAuth.IssueAuthCredentialDeterministic(test32_2, uuid, redemptionTime)
	require.NoError(t, err)

	//
	// Client.
	//
	// Receive credential.
	masterKey := test32_1
	groupSecretParams, err := zkgroup.NewGroupSecretParams(masterKey)
	require.NoError(t, err)
	groupPublicParams, err := groupSecretParams.PublicParams()
	require.NoError(t, err)

	clientZkAuthCipher, err := zkgroup.NewClientZkAuthOperations(serverPublicParams)
	require.NoError(t, err)
	authCredential, err := clientZkAuthCipher.ReceiveAuthCredential(uuid, redemptionTime, authCredentialResponse)
	require.NoError(t, err)

	// Create and decrypt user entry
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)
	uuidCiphertext, err := clientZkGroupCipher.EncryptUUID(uuid)
	require.NoError(t, err)
	uuidOut, err := clientZkGroupCipher.DecryptUUID(uuidCiphertext)
	require.NoError(t, err)
	require.Equal(t, uuid, uuidOut)

	// Create presentation
	presentation, err := clientZkAuthCipher.CreateAuthCredentialPresentationDeterministic(test32_5, groupSecretParams, authCredential)
	require.NoError(t, err)
	authPresentationExpected, _ := hex.DecodeString("000cde979737ed30bbeb16362e4e076945ce02069f727b0ed4c3c33c011e82546e1cdf081fbdf37c03a851ad060bdcbf6378cb4cb16dc3154d08de5439b5323203729d1841b517033af2fd177d30491c138ae723655734f6e5cc01c00696f4e92096d8c33df26ba2a820d42e9735d30f8eeef96d399079073c099f7035523bfe716638659319d3c36ad34c00ef8850f663c4d93030235074312a8878b6a5c5df4fbc7d32935278bfa5996b44ab75d6f06f4c30b98640ad5de74742656c8977567de000000000000000fde69f82ad2dcb4909650ac6b2573841af568fef822b32b45f625a764691a704d11b6f385261468117ead57fa623338e21c66ed846ab65809fcac158066d8e0e444077b99540d886e7dc09555dd6faea2cd3697f1e089f82d54e5d0fe4a185008b5cbc3979391ad71686bc03be7b00ea7e42c08d9f1d75c3a56c27ae2467b80636c0b5343eda7cd578ba88ddb7a0766568477fed63cf531862122c6c15b4a707973d41782cfc0ef4fe6c3115988a2e339015938d2df0a5d30237a2592cc10c05a9e4ef6b695bca99736b1a49ea39606a381ecfb05efe60d28b54823ec5a3680c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100")
	require.Equal(t, zkgroup.AuthCredentialPresentation(authPresentationExpected), presentation)

	// Verify presentation
	uuidCiphertextOut, err := presentation.UUIDCiphertext()
	require.NoError(t, err)
	require.Equal(t, uuidCiphertext, uuidCiphertextOut)
	redemptionTimeOut, err := presentation.RedemptionTime()
	require.NoError(t, err)
	require.Equal(t, redemptionTime, redemptionTimeOut)

	err = serverZkAuth.VerifyAuthCredentialPresentation(groupPublicParams, presentation)
	require.NoError(t, err)
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
