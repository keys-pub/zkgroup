package zkgroup_test

import (
	"encoding/hex"
	"testing"

	"github.com/keys-pub/zkgroup"
	"github.com/stretchr/testify/require"
)

func TestServerSignatures(t *testing.T) {
	serverSecretParams, err := zkgroup.GenerateServerSecretParamsDeterministic(test32)
	require.NoError(t, err)
	serverPublicParams, err := serverSecretParams.PublicParams()
	require.NoError(t, err)

	message := test32_1
	signature, err := serverSecretParams.SignDeterministic(test32_2, message)
	require.NoError(t, err)

	err = serverPublicParams.VerifySignature(message, signature)
	require.NoError(t, err)
	signatureExpected, _ := hex.DecodeString("87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06")
	require.Equal(t, zkgroup.NotarySignature(signatureExpected), signature)

	altered := make([]byte, len(message))
	copy(altered, message)
	altered[0] ^= 1
	err = serverPublicParams.VerifySignature(altered, signature)
	require.EqualError(t, err, "verification failed")
}
