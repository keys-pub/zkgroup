package zkgroup_test

import (
	"testing"

	"github.com/nanu-c/zkgroup"
	"github.com/stretchr/testify/require"
)

func TestUUID(t *testing.T) {
	masterKey := test32_1
	groupSecretParams, err := zkgroup.NewGroupSecretParams(masterKey)
	require.NoError(t, err)
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)

	uuid := zkgroup.UUID(randBytes(16))

	uuidCiphertext, err := clientZkGroupCipher.EncryptUUID(uuid)
	require.NoError(t, err)
	uuidOut, err := clientZkGroupCipher.DecryptUUID(uuidCiphertext)
	require.NoError(t, err)
	require.Equal(t, uuid, uuidOut)

	invalid := zkgroup.UUID(randBytes(32))

	_, err = clientZkGroupCipher.EncryptUUID(invalid)
	require.EqualError(t, err, "invalid uuid length")

	_, err = clientZkGroupCipher.DecryptUUID(invalid)
	require.EqualError(t, err, "invalid input")
}
