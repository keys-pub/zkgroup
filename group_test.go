package zkgroup_test

import (
	"encoding/hex"
	"testing"

	"github.com/nanu-c/zkgroup"
	"github.com/stretchr/testify/require"
)

func TestGroupParams(t *testing.T) {
	masterKey := test32_1
	groupSecretParams, err := zkgroup.NewGroupSecretParams(masterKey)
	require.NoError(t, err)
	groupPublicParams, err := groupSecretParams.PublicParams()
	require.NoError(t, err)

	gid, err := groupPublicParams.GroupIdentifier()
	require.NoError(t, err)
	expected := "84e256730548f8ba09069b223eccc133f599f9827edc7084f8921e4a70cd9e4c"
	require.Equal(t, expected, hex.EncodeToString(gid))
}
