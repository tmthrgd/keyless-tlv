package main

import (
	"crypto"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/gokeyless"
)

var keyExt = regexp.MustCompile(`.+\.key`)

type keyLoader struct {
	sync.RWMutex
	skis map[gokeyless.SKI]crypto.Signer
}

func newKeyLoader() *keyLoader {
	return &keyLoader{
		skis: make(map[gokeyless.SKI]crypto.Signer),
	}
}

func (k *keyLoader) Add(op *gokeyless.Operation, priv crypto.Signer) error {
	ski, err := gokeyless.GetSKI(priv.Public())
	if err != nil {
		return err
	}

	k.Lock()
	k.skis[ski] = priv
	k.Unlock()

	return nil
}

func (k *keyLoader) Get(op *gokeyless.Operation) (priv crypto.Signer, ok bool) {
	if !op.SKI.Valid() {
		return nil, false
	}

	k.RLock()
	priv, ok = k.skis[op.SKI]
	k.RUnlock()

	return
}

func (k *keyLoader) walker(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if info.IsDir() || !keyExt.MatchString(info.Name()) {
		return nil
	}

	in, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	priv, err := helpers.ParsePrivateKeyPEM(in)
	if err != nil {
		priv, err = derhelpers.ParsePrivateKeyDER(in)
	}

	if err != nil {
		return err
	}

	k.Add(nil, priv)
	return nil
}

func (k *keyLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, k.walker)
}
