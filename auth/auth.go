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

type ProofOfWork struct {
	BlockHash   string
	BlockHeight uint64
	Difficulty  uint
	Nonce       uint64
	TxId        string
}

func NewProofOfWork(
	blockHash string,
	blockHeight uint64,
	difficulty uint,
	nonce uint64,
	txId string,
) *ProofOfWork {
	return &ProofOfWork{
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		Difficulty:  difficulty,
		Nonce:       nonce,
		TxId:        txId,
	}
}

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
	chainId string,
	pow *ProofOfWork,
	inputData *commandspb.InputData,
) *commandspb.Transaction {
	inputDataBytes, _ := proto.Marshal(inputData)
	inputDataPacked := bytes.Join([][]byte{
		[]byte(chainId),
		[]byte("\u0000"),
		inputDataBytes,
	}, []byte{})
	hexSig := a.signInputData(keyPair.PrivateKey, inputDataPacked)
	signature := &commandspb.Signature{
		Algo:    "vega/ed25519",
		Version: 1,
		Value:   hexSig,
	}
	proofOfWork := &commandspb.ProofOfWork{Tid: pow.TxId, Nonce: pow.Nonce}
	tx := &commandspb.Transaction{
		Version:   commandspb.TxVersion_TX_VERSION_V3,
		Signature: signature,
		Pow:       proofOfWork,
		InputData: inputDataBytes,
		From:      &commandspb.Transaction_PubKey{PubKey: keyPair.PublicKey},
	}
	return tx
}

func (a *Authenticator) signInputData(privateKey string, inputDataPacked []byte) string {
	hash := sha3.Sum256(inputDataPacked)
	key, _ := hex.DecodeString(privateKey)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(key), hash[:])
	return hex.EncodeToString(sig)
}

func (a *Authenticator) getProofOfWork() *ProofOfWork {
	lastBlock := a.getLastBlock()
	if lastBlock == nil {
		return nil
	}
	difficulty := uint(lastBlock.GetSpamPowDifficulty())
	txId, _ := uuid.NewRandom()
	nonce, _, _ := crypto.PoW(lastBlock.Hash, txId.String(), difficulty, lastBlock.SpamPowHashFunction)
	return NewProofOfWork(
		lastBlock.Hash, lastBlock.Height, difficulty, nonce, txId.String(),
	)
}

func (a *Authenticator) Sign(partyId string, inputData *commandspb.InputData) *commandspb.Transaction {
	lastBlock := a.getLastBlock()
	if lastBlock == nil {
		return nil
	}
	pow := a.getProofOfWork()
	if pow == nil {
		log.Printf("couldn't get proof of work")
		return nil
	}
	inputData.BlockHeight = pow.BlockHeight
	inputData.Nonce = rand.Uint64()
	keyPair := a.wallet.GetByPublicKey(partyId)
	if keyPair == nil {
		log.Printf("couldn't find private key for: %s", partyId)
		return nil
	}
	return a.buildTx(keyPair, lastBlock.ChainId, pow, inputData)
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
