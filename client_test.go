package zkgroup_test

import (
	"encoding/hex"
	"testing"

	"github.com/nanu-c/zkgroup"
	"github.com/stretchr/testify/require"
)

func TestEncryptBlob(t *testing.T) {
	groupSecretParams, err := zkgroup.GenerateGroupSecretParams()
	require.NoError(t, err)
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)
	plaintext := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	ciphertext, err := clientZkGroupCipher.EncryptBlob(plaintext)
	require.NoError(t, err)
	plaintextOut, err := clientZkGroupCipher.DecryptBlob(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, plaintextOut)
}

func TestEncryptBlobDeterministic(t *testing.T) {
	masterKey := test32_1

	groupSecretParams, err := zkgroup.NewGroupSecretParams(masterKey)
	require.NoError(t, err)

	masterKeyOut, err := groupSecretParams.MasterKey()
	require.NoError(t, err)
	require.Equal(t, masterKey, masterKeyOut)

	plaintext, _ := hex.DecodeString("0102030405060708111213141516171819")
	random, _ := hex.DecodeString("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7")

	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)

	ciphertext, err := clientZkGroupCipher.EncryptBlobDeterministic(random, plaintext)
	require.NoError(t, err)

	ciphertextExpected, _ := hex.DecodeString("dd4d032ca9bb75a4a78541b90cb4e95743f3b0dabfc7e11101b098e34f6cf6513940a04c1f20a302692afdc7087f10196000")
	require.Equal(t, ciphertextExpected, ciphertext)

	plaintextOut, err := clientZkGroupCipher.DecryptBlob(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, plaintextOut)

	ciphertext257, _ := hex.DecodeString("5cb5b7bff06e85d929f3511fd194e638cf32a47663868bc8e64d98fb1bbe435ebd21c763ce2d42e85a1b2c169f12f9818ddadcf4b491398b7c5d46a224e1582749f5e2a4a2294caaaaab843a1b7cf6426fd543d09ff32a4ba5f319ca4442b4da34b3e2b5b4f8a52fdc4b484ea86b33db3ebb758dbd9614178f0e4e1f9b2b914f1e786936b62ed2b58b7ae3cb3e7ae0835b9516959837406662b85eac740cef83b60b5aaeaaab95643c2bef8ce87358fabff9d690052beb9e52d0c947e7c986b2f3ce3b7161cec72c08e2c4ade3debe3792d736c0457bc352afb8b6caa48a5b92c1ec05ba808ba8f94c6572ebbf29818912344987573de419dbcc7f1ea0e4b2dd4077b76b381819747ac332e46fa23abfc3338e2f4b081a8a53cba0988eef116764d944f1ce3f20a302692afdc7087f10196000")
	plaintext257, err := clientZkGroupCipher.DecryptBlob(ciphertext257)
	require.NoError(t, err)
	require.Equal(t, plaintext, plaintext257)
}
