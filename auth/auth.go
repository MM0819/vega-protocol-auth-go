package auth

import (
	"bytes"
	"code.vegaprotocol.io/vega/libs/crypto"
	"code.vegaprotocol.io/vega/libs/proto"
	corepb "code.vegaprotocol.io/vega/protos/vega/api/v1"
	commandspb "code.vegaprotocol.io/vega/protos/vega/commands/v1"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math/rand"
)

type Authenticator struct {
	coreNode string
	wallet   *Wallet
}

func NewAuthenticator(coreNode string, wallet *Wallet) *Authenticator {
	return &Authenticator{coreNode: coreNode, wallet: wallet}
}

func (a *Authenticator) getLastBlock() *corepb.LastBlockHeightResponse {
	req := &corepb.LastBlockHeightRequest{}
	coreNode, _ := grpc.Dial(a.coreNode, grpc.WithTransportCredentials(insecure.NewCredentials()))
	coreService := corepb.NewCoreServiceClient(coreNode)
	defer coreNode.Close()
	resp, err := coreService.LastBlockHeight(context.Background(), req)
	if err != nil {
		log.Printf("couldn't get last block: %v", err)
		return nil
	}
	return resp
}

func (a *Authenticator) buildTx(
	keyPair *KeyPair,
	lastBlock *corepb.LastBlockHeightResponse,
	inputData *commandspb.InputData,
) *commandspb.Transaction {
	pow := a.getProofOfWork(lastBlock)
	if pow == nil {
		log.Printf("couldn't get proof of work")
		return nil
	}
	inputDataBytes, _ := proto.Marshal(inputData)
	inputDataPacked := bytes.Join([][]byte{
		[]byte(lastBlock.ChainId),
		[]byte("\u0000"),
		inputDataBytes,
	}, []byte{})
	hexSig := a.signInputData(keyPair.PrivateKey, inputDataPacked)
	signature := &commandspb.Signature{
		Algo:    "vega/ed25519",
		Version: 1,
		Value:   hexSig,
	}
	tx := &commandspb.Transaction{
		Version:   commandspb.TxVersion_TX_VERSION_V3,
		Signature: signature,
		Pow:       pow,
		InputData: inputDataBytes,
		From:      &commandspb.Transaction_PubKey{PubKey: keyPair.PublicKey},
	}
	return tx
}

func (a *Authenticator) signInputData(privateKey string, inputDataPacked []byte) string {
	hash := sha3.Sum256(inputDataPacked)
	if len(privateKey) > 64 {
		privateKey = privateKey[0:64]
	}
	key, _ := hex.DecodeString(privateKey)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(key), hash[:])
	return hex.EncodeToString(sig)
}

func (a *Authenticator) getProofOfWork(lastBlock *corepb.LastBlockHeightResponse) *commandspb.ProofOfWork {
	difficulty := uint(lastBlock.GetSpamPowDifficulty())
	txId, _ := uuid.NewRandom()
	nonce, _, _ := crypto.PoW(lastBlock.Hash, txId.String(), difficulty, lastBlock.SpamPowHashFunction)
	return &commandspb.ProofOfWork{Tid: txId.String(), Nonce: nonce}
}

func (a *Authenticator) Sign(partyId string, inputData *commandspb.InputData) *commandspb.Transaction {
	lastBlock := a.getLastBlock()
	if lastBlock == nil {
		return nil
	}
	inputData.BlockHeight = lastBlock.Height
	inputData.Nonce = rand.Uint64()
	keyPair, err := a.wallet.GetByPublicKey(partyId)
	if err != nil {
		log.Printf("%v", err)
		return nil
	}
	return a.buildTx(keyPair, lastBlock, inputData)
}

func (a *Authenticator) SubmitTx(tx *commandspb.Transaction) *corepb.SubmitTransactionResponse {
	req := &corepb.SubmitTransactionRequest{Tx: tx}
	coreNode, _ := grpc.Dial(a.coreNode, grpc.WithTransportCredentials(insecure.NewCredentials()))
	coreService := corepb.NewCoreServiceClient(coreNode)
	defer coreNode.Close()
	resp, err := coreService.SubmitTransaction(context.Background(), req)
	if err != nil {
		log.Printf("couldn't submit tx: %v", err)
	} else if !resp.Success {
		log.Printf("tx = %s; code = %d; data = %s", resp.TxHash, resp.Code, resp.Data)
	}
	return resp
}
