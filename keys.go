package main

import (
	"crypto"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	gkserver "github.com/cloudflare/gokeyless/server"
)

type keyLoader struct {
	gkserver.Keystore
	gsrv gkserver.Server
}

func newKeyLoader() *keyLoader {
	keys := gkserver.NewKeystore()
	return &keyLoader{
		Keystore: keys,
		gsrv:     gkserver.Server{Keys: keys},
	}
}

func (*keyLoader) loadKey(in []byte) (crypto.Signer, error) {
	if priv, err := helpers.ParsePrivateKeyPEM(in); err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

func (k *keyLoader) LoadFromDir(dir string) error {
	return k.gsrv.LoadKeysFromDir(dir, k.loadKey)
}
