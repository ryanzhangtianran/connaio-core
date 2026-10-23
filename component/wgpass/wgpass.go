// Package wgpass derives a reverse tunnel's WireGuard keys from its password, the same at both
// ends: Connaio's (component/reverse) and the server's (connaio-relay).
package wgpass

import (
	"crypto/ecdh"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"sync"
)

// salt and rounds make the keys: changing either breaks every tunnel set up before.
const (
	salt   = "connaio-wireguard"
	rounds = 600_000
)

// Keys are a tunnel's: both ends' private keys and the pre-shared key.
type Keys struct {
	Local  *ecdh.PrivateKey // Connaio's end
	Server *ecdh.PrivateKey // connaio-relay's
	PSK    []byte
}

var derived sync.Map // password -> Keys: a derivation takes a moment, and every reload parses again

// Derive is PBKDF2-SHA256 of password to 96 bytes: Connaio's private key, the server's, then the
// pre-shared key.
func Derive(password string) (Keys, error) {
	if len(password) < 8 {
		return Keys{}, errors.New("password is shorter than 8")
	}
	if k, ok := derived.Load(password); ok {
		return k.(Keys), nil
	}
	seed, err := pbkdf2.Key(sha256.New, password, []byte(salt), rounds, 96)
	if err != nil {
		return Keys{}, err
	}
	local, _ := ecdh.X25519().NewPrivateKey(seed[:32]) // any 32 bytes are a key
	server, _ := ecdh.X25519().NewPrivateKey(seed[32:64])
	k := Keys{local, server, seed[64:]}
	derived.Store(password, k)
	return k, nil
}
