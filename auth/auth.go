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
	"fmt"
	"github.com/google/uuid"
	"github.com/sasha-s/go-deadlock"
	"golang.org/x/crypto/sha3"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

const NumberOfPastBlocks = 100
const TxPerBlock = 2

type ProofOfWork struct {
	BlockHash   string
	BlockHeight uint64
	Difficulty  uint
	Nonce       uint64
	TxId        string
	Used        bool
}

func NewProofOfWork(
	blockHash string,
	blockHeight uint64,
	difficulty uint,
	nonce uint64,
	txId string,
	used bool,
) *ProofOfWork {
	return &ProofOfWork{
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		Difficulty:  difficulty,
		Nonce:       nonce,
		TxId:        txId,
		Used:        used,
	}
}

type Authenticator struct {
	coreNode   string
	wallet     *Wallet
	mu         deadlock.RWMutex
	powByBlock map[uint64][]*ProofOfWork
}

func NewAuthenticator(coreNode string, wallet *Wallet) *Authenticator {
	authenticator := &Authenticator{
		coreNode:   coreNode,
		wallet:     wallet,
		powByBlock: map[uint64][]*ProofOfWork{},
	}
	go func() {
		for range time.NewTicker(time.Second).C {
			authenticator.computeProofOfWork()
		}
	}()
	go func() {
		for range time.NewTicker(time.Second).C {
			authenticator.removeOldProofOfWork()
		}
	}()
	return authenticator
}

func (a *Authenticator) removeOldProofOfWork() {
	lastBlock := a.getLastBlock()
	if lastBlock == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	oldestBlock := lastBlock.Height - uint64(math.Round(0.8*NumberOfPastBlocks))
	for _, height := range maps.Keys(a.powByBlock) {
		if height <= oldestBlock {
			delete(a.powByBlock, height)
		}
	}
}

func (a *Authenticator) computeProofOfWork() {
	lastBlock := a.getLastBlock()
	if lastBlock == nil {
		return
	}
	a.mu.Lock()
	if ok := a.powByBlock[lastBlock.Height]; ok == nil {
		a.powByBlock[lastBlock.Height] = make([]*ProofOfWork, 0)
	}
	powCount := len(a.powByBlock[lastBlock.Height])
	a.mu.Unlock()
	if powCount == 0 {
		total := 10.0
		var wg sync.WaitGroup
		for i := 0; i < int(total); i++ {
			wg.Add(1)
			i := i
			go func() {
				difficulty := uint(lastBlock.GetSpamPowDifficulty())
				extraZeroes := uint(math.Floor(float64(i+1) / TxPerBlock))
				difficulty = difficulty + extraZeroes
				txId, _ := uuid.NewRandom()
				nonce, _, _ := crypto.PoW(lastBlock.Hash, txId.String(), difficulty, lastBlock.SpamPowHashFunction)
				pow := NewProofOfWork(
					lastBlock.Hash, lastBlock.Height, difficulty, nonce, txId.String(), false,
				)
				a.mu.Lock()
				a.powByBlock[lastBlock.Height] = append(a.powByBlock[lastBlock.Height], pow)
				a.mu.Unlock()
				wg.Done()
			}()
		}
		wg.Wait()
		fmt.Printf("computed %f PoW\n", total)
	}
}

func (a *Authenticator) HasProofOfWork() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	var result = false
	for _, height := range maps.Keys(a.powByBlock) {
		for _, pow := range a.powByBlock[height] {
			if !pow.Used {
				result = true
				break
			}
		}
	}
	return result
}

func (a *Authenticator) taintProofOfWork(blockHeight uint64, txId string) {
	powList := a.powByBlock[blockHeight]
	if powList != nil {
		for i, pow := range powList {
			if pow.TxId == txId {
				powList[i].Used = true
			}
		}
	}
}

func (a *Authenticator) getProofOfWork() *ProofOfWork {
	powList := make([]*ProofOfWork, 0)
	for _, height := range maps.Keys(a.powByBlock) {
		for _, pow := range a.powByBlock[height] {
			if !pow.Used {
				powList = append(powList, pow)
			}
		}
	}
	sort.Slice(powList, func(i, j int) bool {
		if powList[i].BlockHeight == powList[j].BlockHeight {
			return powList[i].Difficulty < powList[j].Difficulty
		}
		return powList[i].BlockHeight < powList[j].BlockHeight
	})
	if len(powList) == 0 {
		fmt.Println("waiting for proof of work...")
		time.Sleep(time.Second)
		return a.getProofOfWork()
	} else {
		pow := powList[0]
		a.taintProofOfWork(pow.BlockHeight, pow.TxId)
		return pow
	}
}

func (a *Authenticator) getLastBlock() *corepb.LastBlockHeightResponse {
	req := &corepb.LastBlockHeightRequest{}
	coreNode, _ := grpc.Dial(a.coreNode, grpc.WithTransportCredentials(insecure.NewCredentials()))
	coreService := corepb.NewCoreServiceClient(coreNode)
	defer coreNode.Close()
	resp, err := coreService.LastBlockHeight(context.Background(), req)
	if err != nil {
		log.Printf("couldn't get last block: %v\n", err)
		return nil
	}
	return resp
}

func (a *Authenticator) buildTx(
	keyPair *KeyPair,
	lastBlock *corepb.LastBlockHeightResponse,
	inputData *commandspb.InputData,
) *commandspb.Transaction {
	a.mu.Lock()
	a.mu.Unlock()
	pow := a.getProofOfWork()
	if pow == nil {
		log.Println("couldn't get proof of work")
		return nil
	}
	inputData.BlockHeight = pow.BlockHeight
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
	if len(privateKey) > 64 {
		privateKey = privateKey[0:64]
	}
	key, _ := hex.DecodeString(privateKey)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(key), hash[:])
	return hex.EncodeToString(sig)
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
		log.Printf("%v\n", err)
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
		log.Printf("couldn't submit tx: %v\n", err)
	} else if !resp.Success {
		log.Printf("tx = %s; code = %d; data = %s\n", resp.TxHash, resp.Code, resp.Data)
	}
	return resp
}
