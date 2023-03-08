package auth

import (
	"crypto/ed25519"
	"fmt"
	"github.com/tyler-smith/go-bip39"
	"github.com/vitelabs/go-vite/common/db/xleveldb/errors"
	"github.com/vitelabs/go-vite/wallet/hd-bip/derivation"
	"golang.org/x/exp/maps"
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
	key         *derivation.Key
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
		key, _ := derivation.DeriveForPath(fmt.Sprintf("m/44'/1789'/0'/%d'", idx), w.seed)
		privateKey := ed25519.NewKeyFromSeed(key.Key)
		privateKeyHex := fmt.Sprintf("%x", key.Key)
		publicKeyHex := fmt.Sprintf("%x", privateKey.Public())
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
