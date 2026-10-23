package wgpass

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDerive pins the derivation: tunnels set up before must keep their keys.
func TestDerive(t *testing.T) {
	k, err := Derive("correct horse battery")
	require.NoError(t, err)
	b64 := base64.StdEncoding.EncodeToString
	require.Equal(t, "oVjsj016MZbLN+AM0eLyzCu0VwDh4y7kpEFI7A6vsMI=", b64(k.Local.Bytes()))
	require.Equal(t, "4zCKEhvY+pLgB4yMSwMZmD4fW/1AzCseh5zo0iR2wkU=", b64(k.Server.PublicKey().Bytes()))
	require.Equal(t, "lUG3Ya9A//PhAZUZxPyiep6bpJu5t1/LXCaWg/RAZr8=", b64(k.PSK))
	_, err = Derive("1234567")
	require.Error(t, err)
}
