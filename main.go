package main

import (
	"code.vegaprotocol.io/vega/protos/vega"
	commandspb "code.vegaprotocol.io/vega/protos/vega/commands/v1"
	"log"
	"vega-protocol-auth/auth"
)

const Mnemonic = "voyage credit question ride kite race ladder indoor net select margin canvas zone talk have"
const CoreNode = "n08.testnet.vega.xyz:3002"
const ProposalId = "0f4d06000087b989f613bf3a651842b88874d70c4b8b3161c7257837447c3400"

func main() {
	wallet := auth.NewWallet(Mnemonic)
	authenticator := auth.NewAuthenticator(CoreNode, wallet)
	partyId := wallet.Get(0).PublicKey
	inputData := &commandspb.InputData{
		Command: &commandspb.InputData_VoteSubmission{
			VoteSubmission: &commandspb.VoteSubmission{
				ProposalId: ProposalId,
				Value:      vega.Vote_VALUE_YES,
			},
		},
	}
	tx := authenticator.Sign(partyId, inputData)
	log.Printf("%v", tx)
	resp := authenticator.SubmitTx(tx)
	log.Printf("%v", resp)
}
