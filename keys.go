package main

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
)

var keyExt = regexp.MustCompile(`.+\.key`)

type KeyLoader struct {
	sync.RWMutex
	skis map[SKI]crypto.Signer
}

func NewKeyLoader() *KeyLoader {
	return &KeyLoader{
		skis: make(map[SKI]crypto.Signer),
	}
}

func (k *KeyLoader) GetKey(ski SKI) (priv crypto.Signer, err error) {
	var ok bool

	if ski.Valid() {
		k.RLock()
		priv, ok = k.skis[ski]
		k.RUnlock()
	}

	if !ok {
		err = ErrorKeyNotFound
	}

	return
}

func (k *KeyLoader) walker(path string, info os.FileInfo, err error) error {
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
		if err != nil {
			privSSH, err := ssh.ParseRawPrivateKey(in)
			if err != nil {
				return err
			}

			if key, ok := privSSH.(*ed25519.PrivateKey); ok {
				priv = *key
			} else {
				return fmt.Errorf("unsupported key type %T", privSSH)
			}
		}
	}

	ski, err := GetSKI(priv.Public())
	if err != nil {
		return err
	}

	k.Lock()
	k.skis[ski] = priv
	k.Unlock()

	return nil
}

func (k *KeyLoader) LoadFromDir(dir string) error {
	return filepath.Walk(dir, k.walker)
}
