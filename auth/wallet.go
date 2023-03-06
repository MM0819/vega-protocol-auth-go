package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/tyler-smith/go-bip39"
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
	key          *derivation.Key
	seed         []byte
	derivedKeys  map[uint]*KeyPair
	importedKeys map[string]*KeyPair
}

func NewWallet(mnemonic string) *Wallet {
	if len(mnemonic) == 0 {
		panic("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, "")
	return &Wallet{
		seed:         seed,
		derivedKeys:  map[uint]*KeyPair{},
		importedKeys: map[string]*KeyPair{},
	}
}

func (w *Wallet) Get(idx uint) *KeyPair {
	keyPair := w.derivedKeys[idx]
	if keyPair == nil {
		// TODO - what do we use for the derivation path in the web wallet??
		key, _ := derivation.DeriveForPath(fmt.Sprintf("m/44'/0819'/%d'", idx), w.seed)
		privateKey := ed25519.NewKeyFromSeed(key.Key)
		privateKeyHex := fmt.Sprintf("%x", key.Key)
		publicKeyHex := fmt.Sprintf("%x", privateKey.Public())
		w.derivedKeys[idx] = NewKeyPair(privateKeyHex, publicKeyHex)
	}
	return w.derivedKeys[idx]
}

func (w *Wallet) GetByPublicKey(publicKey string) *KeyPair {
	publicKey = strings.ToLower(publicKey)
	keyPair := w.importedKeys[publicKey]
	if keyPair == nil {
		for _, k := range maps.Values(w.derivedKeys) {
			if k.PublicKey == publicKey {
				keyPair = k
				break
			}
		}
	}
	return keyPair
}

func (w *Wallet) Import(privateKey string) {
	privateKey = strings.ToLower(privateKey)
	pk, _ := hex.DecodeString(privateKey)
	key := ed25519.NewKeyFromSeed(pk)
	publicKey := fmt.Sprintf("%x", key.Public())
	w.importedKeys[publicKey] = NewKeyPair(privateKey, publicKey)
}
