package vdf_test

import (
	"golang.org/x/crypto/sha3"
	nekrovdf "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"testing"
)

func getChallenge(seed string) [32]byte {
	return sha3.Sum256([]byte(seed))
}

func TestProveVerify(t *testing.T) {
	difficulty := uint32(10000)
	challenge := getChallenge("TestProveVerify")
	solution := vdf.WesolowskiSolve(challenge, difficulty)
	isOk := vdf.WesolowskiVerify(challenge, difficulty, solution)
	if !isOk {
		t.Fatalf("Verification failed")
	}
}

func TestProveRustVerifyNekro(t *testing.T) {
	difficulty := uint32(100)
	challenge := getChallenge("TestProveRustVerifyNekro")

	for i := 0; i < 100; i++ {
		solution := vdf.WesolowskiSolve(challenge, difficulty)
		nekroVdf := nekrovdf.New(difficulty, challenge)
		isOk := nekroVdf.Verify(solution)
		if !isOk {
			t.Fatalf("Verification failed")
		}
		challenge = sha3.Sum256(solution[:])
	}
}

func TestProveNekroVerifyRust(t *testing.T) {
	difficulty := uint32(100)
	challenge := getChallenge("TestProveNekroVerifyRust")

	for i := 0; i < 100; i++ {
		nekroVdf := nekrovdf.New(difficulty, challenge)
		nekroVdf.Execute()
		proof := nekroVdf.GetOutput()
		isOk := vdf.WesolowskiVerify(challenge, difficulty, proof)
		if !isOk {
			t.Fatalf("Verification failed")
		}
		challenge = sha3.Sum256(proof[:])
	}
}
