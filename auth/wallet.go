package auth

import (
	"fmt"
	"github.com/tyler-smith/go-bip39"
	"github.com/vegaprotocol/go-slip10"
	"github.com/vitelabs/go-vite/common/db/xleveldb/errors"
	"golang.org/x/exp/maps"
	"log"
	"strings"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func NewKeyPair(privateKey string, publicKey string) *KeyPair {
	return &KeyPair{PrivateKey: privateKey, PublicKey: publicKey}
}

type Wallet struct {
	seed        []byte
	derivedKeys map[uint]*KeyPair
}

func NewWallet(mnemonic string) *Wallet {
	if len(mnemonic) == 0 {
		panic("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, "")
	return &Wallet{
		seed:        seed,
		derivedKeys: map[uint]*KeyPair{},
	}
}

func (w *Wallet) Get(idx uint) *KeyPair {
	keyPair := w.derivedKeys[idx]
	if keyPair == nil {
		path := fmt.Sprintf("m/1789'/0'/%d'", idx)
		key, err := slip10.DeriveForPath(path, w.seed)
		if err != nil {
			log.Printf("cannot derive key: %v", err)
			return nil
		}
		publicKey, privateKey := key.Keypair()
		privateKeyHex := fmt.Sprintf("%x", privateKey)
		publicKeyHex := fmt.Sprintf("%x", publicKey)
		w.derivedKeys[idx] = NewKeyPair(privateKeyHex, publicKeyHex)
	}
	return w.derivedKeys[idx]
}

func (w *Wallet) GetByPublicKey(publicKey string) (*KeyPair, error) {
	publicKey = strings.ToLower(publicKey)
	for _, k := range maps.Values(w.derivedKeys) {
		if k.PublicKey == publicKey {
			return k, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("cannot find key pair for pub key %s", publicKey))
}
