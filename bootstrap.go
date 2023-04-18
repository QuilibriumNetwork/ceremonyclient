package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
	bls48581 "source.quilibrium.com/quilibrium/ceremonyclient/ec/bls48581"
)

const SEQUENCER_ACCEPTING = "\"ACCEPTING\""

type PowersOfTauJson struct {
	G1Affines []string `json:"G1Powers"`
	G2Affines []string `json:"G2Powers"`
}

type ContributionJson struct {
	PowersOfTau   PowersOfTauJson `json:"powersOfTau"`
	PotPubKey     string          `json:"potPubKey"`
	VoucherPubKey string          `json:"voucherPubKey"`
}

type BatchContribution struct {
	Contribution Contribution
}

type PowersOfTau struct {
	G1Affines []*bls48581.ECP
	G2Affines []*bls48581.ECP8
}

type Contribution struct {
	NumG1Powers int
	NumG2Powers int
	PowersOfTau PowersOfTau
	PotPubKey   *bls48581.ECP8
}

var voucherPubKey ed448.PublicKey
var voucher ed448.PrivateKey
var secret *bls48581.BIG
var bcj *ContributionJson = &ContributionJson{}

func JoinLobby() {
	var err error
	if voucherPubKey == nil {
		voucherPubKey, voucher, err = ed448.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	}

	sig, err := voucher.Sign(rand.Reader, []byte("JOIN"), ed448.SignerOptions{Hash: crypto.Hash(0), Scheme: ed448.ED448})
	if err != nil {
		panic(err)
	}

	reqHex := hex.EncodeToString(voucherPubKey)
	sigHex := hex.EncodeToString(sig)

	req, err := http.NewRequest("POST", HOST+"join", bytes.NewBuffer([]byte(reqHex)))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", sigHex)

	client := http.DefaultClient
	resp, err := client.Do(req)

	fmt.Println("Connected to sequencer!")

	if err != nil {
		panic(err)
	} else {
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		} else {
			return
		}
	}
}

func GetSequencerState() string {
	req, err := http.NewRequest("POST", HOST+"sequencer_state", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	sequencerState, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(sequencerState)
}

func Bootstrap() {
	secretBytes := make([]byte, (8 * int(bls48581.MODBYTES)))
	rand.Read(secretBytes)
	secret = bls48581.FromBytes(secretBytes)
	secret.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))

	bcjRes, err := http.DefaultClient.Post(HOST+"current_state", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		panic(err)
	}

	defer bcjRes.Body.Close()

	bcjBytes, err := io.ReadAll(bcjRes.Body)
	if err != nil {
		panic(err)
	}

	if err := json.Unmarshal(bcjBytes, bcj); err != nil {
		// message is not conformant, we are in validating phase
		panic(err)
	}

	contributeWithSecrets(secret)
}

func contributeWithSecrets(secret *bls48581.BIG) error {
	updatePowersOfTau(secret)
	updateWitness(secret)

	return nil
}

var xi []*bls48581.BIG

func updatePowersOfTau(secret *bls48581.BIG) {
	xi = append(xi, bls48581.NewBIGint(1))

	for i := 0; i < 65536; i++ {
		xi = append(xi, bls48581.Modmul(xi[i], secret, bls48581.NewBIGints(bls48581.CURVE_Order)))
	}

	wg := sync.WaitGroup{}
	wg.Add(65536)

	for i := 0; i < 65536; i++ {
		i := i
		go func() {
			g1PowersString := strings.TrimPrefix(bcj.PowersOfTau.G1Affines[i], "0x")
			g1PowersHex, _ := hex.DecodeString(g1PowersString)
			g1Power := bls48581.ECP_fromBytes(g1PowersHex)

			if g1Power.Equals(bls48581.NewECP()) {
				panic("invalid g1Power")
			}

			g1Power = g1Power.Mul(xi[i])
			g1Power.ToBytes(g1PowersHex, true)
			bcj.PowersOfTau.G1Affines[i] = "0x" + hex.EncodeToString(g1PowersHex)

			if i < 257 {
				g2PowersString := strings.TrimPrefix(bcj.PowersOfTau.G2Affines[i], "0x")
				g2PowersHex, _ := hex.DecodeString(g2PowersString)
				g2Power := bls48581.ECP8_fromBytes(g2PowersHex)

				if g2Power.Equals(bls48581.NewECP8()) {
					panic("invalid g2Power")
				}

				g2Power = g2Power.Mul(xi[i])
				g2Power.ToBytes(g2PowersHex, true)
				bcj.PowersOfTau.G2Affines[i] = "0x" + hex.EncodeToString(g2PowersHex)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

func updateWitness(secret *bls48581.BIG) {
	g2PowersString := strings.TrimPrefix(bcj.PotPubKey, "0x")
	g2PowersHex, _ := hex.DecodeString(g2PowersString)
	g2Power := bls48581.ECP8_fromBytes(g2PowersHex)
	x := bls48581.Modmul(bls48581.NewBIGint(1), secret, bls48581.NewBIGints(bls48581.CURVE_Order))

	if g2Power.Equals(bls48581.NewECP8()) {
		panic("invalid g2Power")
	}

	g2Power = g2Power.Mul(x)
	g2Power.ToBytes(g2PowersHex, true)
	bcj.PotPubKey = "0x" + hex.EncodeToString(g2PowersHex)
	bcj.VoucherPubKey = "0x" + hex.EncodeToString(voucherPubKey)
}

func ContributeAndGetVoucher() {
	sendBytes, err := json.Marshal(bcj)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", HOST+"contribute", bytes.NewBuffer(sendBytes))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")
	sig, err := voucher.Sign(rand.Reader, []byte(bcj.PotPubKey), ed448.SignerOptions{Hash: crypto.Hash(0), Scheme: ed448.ED448})
	if err != nil {
		panic(err)
	}

	sigHex := hex.EncodeToString(sig)
	req.Header.Set("Authorization", sigHex)

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	filename := "quil_voucher.hex"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	} else {
		fmt.Println("Voucher file name not provided, writing to quil_voucher.hex")
	}

	if err := os.WriteFile(filename, []byte(hex.EncodeToString(voucher)), 0644); err != nil {
		fmt.Println("Could not write voucher to file, voucher hex string below:")
		fmt.Println(hex.EncodeToString(voucher))
	}
}
