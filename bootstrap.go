package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/sync/errgroup"
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

type CeremonyState struct {
	PowersOfTau    PowersOfTauJson `json:"powersOfTau"`
	PotPubKey      string          `json:"potPubKey"`
	Witness        Witness         `json:"witness"`
	VoucherPubKeys []string        `json:"voucherPubKeys"`
}

type Witness struct {
	RunningProducts []string `json:"runningProducts"`
	PotPubKeys      []string `json:"potPubKeys"`
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

func VerifyState() {
	csjRes, err := http.DefaultClient.Post(HOST+"current_state", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		panic(err)
	}

	defer csjRes.Body.Close()

	csjBytes, err := io.ReadAll(csjRes.Body)
	if err != nil {
		panic(err)
	}

	currentStateJson := &CeremonyState{}

	if err := json.Unmarshal(csjBytes, currentStateJson); err != nil {
		// message is not conformant, we are in validating phase
		panic(err)
	}

	verifyState(currentStateJson)
}

func CheckVoucherInclusion(path string) {
	csjRes, err := http.DefaultClient.Post(HOST+"current_state", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		panic(err)
	}

	defer csjRes.Body.Close()

	csjBytes, err := io.ReadAll(csjRes.Body)
	if err != nil {
		panic(err)
	}

	currentStateJson := &CeremonyState{}

	if err := json.Unmarshal(csjBytes, currentStateJson); err != nil {
		// message is not conformant, we are in validating phase
		panic(err)
	}

	voucherHex, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	decodedVoucher, err := hex.DecodeString(string(voucherHex))
	if err != nil {
		panic(err)
	}

	privKey := ed448.PrivateKey(decodedVoucher)

	verifyPubKey := "0x" + hex.EncodeToString(privKey.Public().(ed448.PublicKey))

	for i, v := range currentStateJson.VoucherPubKeys {
		if v == verifyPubKey {
			fmt.Printf("Voucher pubkey found at index %d\n", i)
			os.Exit(0)
		}
	}

	panic(errors.New("voucher not found"))
}

func verifyState(currentState *CeremonyState) {
	wg := &errgroup.Group{}
	// This limit needs to be low – this check is a very painfully CPU intensive operation
	wg.SetLimit(8)

	fmt.Println("Checking running products of witnesses...")

	// check the pairings
	for j := 0; j < len(currentState.Witness.RunningProducts)-1; j++ {
		j := j
		wg.Go(func() error {
			fmt.Printf("Checking witness at %d\n", j)

			currRunningProductHex := strings.TrimPrefix(currentState.Witness.RunningProducts[j], "0x")
			currRunningProductBytes, err := hex.DecodeString(currRunningProductHex)
			if err != nil {
				return fmt.Errorf("could not decode G1 at %d", j)
			}

			currRunningProduct := bls48581.ECP_fromBytes(currRunningProductBytes)
			if currRunningProduct == nil {
				return fmt.Errorf("could not convert G1 at %d", j)
			}

			nextRunningProductHex := strings.TrimPrefix(currentState.Witness.RunningProducts[j+1], "0x")
			nextRunningProductBytes, err := hex.DecodeString(nextRunningProductHex)
			if err != nil {
				return fmt.Errorf("could not decode next G1 at %d", j)
			}

			nextRunningProduct := bls48581.ECP_fromBytes(nextRunningProductBytes)
			if nextRunningProduct == nil {
				return fmt.Errorf("could not convert next G1 at %d", j)
			}

			potPubKeyHex := strings.TrimPrefix(currentState.Witness.PotPubKeys[j+1], "0x")
			potPubKeyBytes, err := hex.DecodeString(potPubKeyHex)
			if err != nil {
				return fmt.Errorf("could not decode POT pubkey at %d", j)
			}

			potPubKey := bls48581.ECP8_fromBytes(potPubKeyBytes)
			if potPubKey == nil {
				return fmt.Errorf("could not convert POT pubkey at %d", j)
			}

			prevPotPubKeyHex := strings.TrimPrefix(currentState.Witness.PotPubKeys[j], "0x")
			prevPotPubKeyBytes, err := hex.DecodeString(prevPotPubKeyHex)
			if err != nil {
				return fmt.Errorf("could not decode POT pubkey at %d", j)
			}

			prevPotPubKey := bls48581.ECP8_fromBytes(prevPotPubKeyBytes)
			if prevPotPubKey == nil {
				return fmt.Errorf("could not convert POT pubkey at %d", j)
			}

			if !pairCheck(potPubKey, currRunningProduct, prevPotPubKey, nextRunningProduct) {
				return fmt.Errorf("pairing check failed")
			}

			return nil
		})
	}

	fmt.Println("Checking latest witness parity...")

	// Check that the last running product is equal to G1 first power.
	lastRunningProductIdx := len(currentState.Witness.RunningProducts) - 1
	lastRunningProduct := currentState.Witness.RunningProducts[lastRunningProductIdx]
	if lastRunningProduct != currentState.PowersOfTau.G1Affines[1] {
		panic("mismatched running products for G1")
	}

	// Check that the first running product is the tau^0 power.
	firstRunningProduct := currentState.Witness.RunningProducts[0]
	if firstRunningProduct != currentState.PowersOfTau.G1Affines[0] {
		panic("mismatched first product for G1")
	}

	fmt.Println("Checking coherency of G1 powers...")
	// Check coherency of powers
	for j := 0; j < 65535; j++ {
		j := j
		wg.Go(func() error {
			fmt.Printf("Checking coherency of G1 at %d\n", j)
			baseTauG2Hex := strings.TrimPrefix(currentState.PowersOfTau.G2Affines[1], "0x")
			baseTauG2Bytes, err := hex.DecodeString(baseTauG2Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G2 at %d", j)
			}

			baseTauG2 := bls48581.ECP8_fromBytes(baseTauG2Bytes)
			if baseTauG2 == nil {
				return fmt.Errorf("failed to convert for G2 at %d", j)
			}

			currG1Hex := strings.TrimPrefix(currentState.PowersOfTau.G1Affines[j], "0x")
			currG1Bytes, err := hex.DecodeString(currG1Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G1 at %d", j)
			}

			currG1 := bls48581.ECP_fromBytes(currG1Bytes)
			if currG1 == nil {
				return fmt.Errorf("failed to convert for G1 at %d", j)
			}

			nextG1Hex := strings.TrimPrefix(currentState.PowersOfTau.G1Affines[j+1], "0x")
			nextG1Bytes, err := hex.DecodeString(nextG1Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G1 at %d", j+1)
			}

			nextG1 := bls48581.ECP_fromBytes(nextG1Bytes)
			if nextG1 == nil {
				return fmt.Errorf("failed to convert for G1 at %d", j+1)
			}

			if !pairCheck(baseTauG2, currG1, bls48581.ECP8_generator(), nextG1) {
				return fmt.Errorf("pairing check failed")
			}

			return nil
		})
	}

	fmt.Println("Checking coherency of G2 powers...")

	// Check G2 powers are coherent
	for j := 0; j < 256; j++ {
		j := j
		wg.Go(func() error {
			fmt.Printf("Checking coherency of G2 at %d\n", j)
			baseTauG1Hex := strings.TrimPrefix(currentState.PowersOfTau.G1Affines[1], "0x")
			baseTauG1Bytes, err := hex.DecodeString(baseTauG1Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G1 at %d", j)
			}

			baseTauG1 := bls48581.ECP_fromBytes(baseTauG1Bytes)
			if baseTauG1 == nil {
				return fmt.Errorf("failed to convert for G1 at %d", j)
			}

			currG2Hex := strings.TrimPrefix(currentState.PowersOfTau.G2Affines[j], "0x")
			currG2Bytes, err := hex.DecodeString(currG2Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G2 at %d", j)
			}

			currG2 := bls48581.ECP8_fromBytes(currG2Bytes)
			if currG2 == nil {
				return fmt.Errorf("failed to convert for G1 at %d", j)
			}

			nextG2Hex := strings.TrimPrefix(currentState.PowersOfTau.G2Affines[j+1], "0x")
			nextG2Bytes, err := hex.DecodeString(nextG2Hex)
			if err != nil {
				return fmt.Errorf("failed to decode for G2 at %d", j+1)
			}

			nextG2 := bls48581.ECP8_fromBytes(nextG2Bytes)
			if nextG2 == nil {
				return fmt.Errorf("failed to convert for G2 at %d", j+1)
			}

			if !pairCheck(currG2, baseTauG1, nextG2, bls48581.ECP_generator()) {
				return fmt.Errorf("pairing check failed")
			}

			return nil
		})
	}

	if err := wg.Wait(); err != nil {
		panic(fmt.Errorf("error validating transcript: %w", err))
	}

	fmt.Println("Current state is valid Powers of Tau!")
}

func pairCheck(G21 *bls48581.ECP8, G11 *bls48581.ECP, G22 *bls48581.ECP8, G12 *bls48581.ECP) bool {
	G12.Neg()
	v := bls48581.Ate2(G21, G11, G22, G12)
	v = bls48581.Fexp(v)

	if !v.Isunity() {
		fmt.Println("pairing check failed")
		return false
	}

	return true
}
