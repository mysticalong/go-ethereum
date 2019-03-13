package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/consensus/poi"

	"github.com/ethereum/go-ethereum/log"
)

func main() {
	fmt.Println("this is a info helper for polo miner only! q=quit; enter=continue.")
	in := bufio.NewReader(os.Stdin)

	text, err := in.ReadString('\n')
	if err != nil {
		log.Crit("Failed to read user input", "err", err)
	}
	if strings.TrimSpace(text) == "q" {
		os.Exit(0)
	}
	poi.InitPCR()
	quoted, _, err := poi.TPMSign("")
	if err != nil {
		log.Crit(err.Error())
	}
	fmt.Println("\n***************MINER INFO***************")
	// fmt.Printf("quoted = %x\n", quoted)
	// fmt.Printf("signature = %x\n", signature)
	pcr := quoted[len(quoted)-44:] //PCR is  part of Quoted named TPMS_QUOTE_INFO
	fmt.Printf("PCR = %x\n", pcr)
	pubKey, err := poi.GetPubKeyBytes()
	if err != nil {
		log.Crit(err.Error())
	}
	fmt.Printf("pubKey = %x\n", pubKey)
	signer := poi.SignerFromPubKey(pubKey)
	fmt.Printf("signer = %x\n", signer)
	fmt.Println("*****************************************")
}
