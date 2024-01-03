//
// Copyright (c) 2019 harmony-one
//
// SPDX-License-Identifier: MIT
//

package vdf

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/big"
	"sort"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/iqc"
)

// Creates L and k parameters from papers, based on how many iterations need to be
// performed, and how much memory should be used.
func approximateParameters(T uint32) (int, int, int) {
	//log_memory = math.log(10000000, 2)
	log_memory := math.Log(10000000) / math.Log(2)
	log_T := math.Log(float64(T)) / math.Log(2)
	L := 1

	if log_T-log_memory > 0 {
		L = int(math.Ceil(math.Pow(2, log_memory-20)))
	}

	// Total time for proof: T/k + L * 2^(k+1)
	// To optimize, set left equal to right, and solve for k
	// k = W(T * log(2) / (2 * L))  / log(2), where W is the product log function
	// W can be approximated by log(x) - log(log(x)) + 0.25
	intermediate := float64(T) * math.Log(2) / float64(2*L)
	k := int(math.Max(math.Round(math.Log(intermediate)-math.Log(math.Log(intermediate))+0.25), 1))

	// 1/w is the approximate proportion of time spent on the proof
	w := int(math.Floor(float64(T)/(float64(T)/float64(k)+float64(L)*math.Pow(2, float64(k+1)))) - 2)

	return L, k, w
}

func iterateSquarings(x *iqc.ClassGroup, powers_to_calculate []int, stop <-chan struct{}) map[int]*iqc.ClassGroup {
	powers_calculated := make(map[int]*iqc.ClassGroup)

	previous_power := 0
	currX := x.Clone()
	sort.Ints(powers_to_calculate)
	for _, current_power := range powers_to_calculate {

		for i := 0; i < current_power-previous_power; i++ {
			currX = currX.Pow(2)
			if currX == nil {
				return nil
			}
		}

		previous_power = current_power
		powers_calculated[current_power] = currX

		select {
		case <-stop:
			return nil
		default:
		}
	}

	return powers_calculated
}

func GenerateVDF(seed []byte, iterations, int_size_bits uint32) ([]byte, []byte) {
	return GenerateVDFWithStopChan(seed, iterations, int_size_bits, nil)
}

func GenerateVDFWithStopChan(seed []byte, iterations, int_size_bits uint32, stop <-chan struct{}) ([]byte, []byte) {
	D := iqc.CreateDiscriminant(seed, int_size_bits)
	x := iqc.NewClassGroupFromAbDiscriminant(big.NewInt(2), big.NewInt(1), D)

	y, proof := calculateVDF(D, x, iterations, int_size_bits, stop)

	if (y == nil) || (proof == nil) {
		return nil, nil
	} else {
		return y.Serialize(), proof.Serialize()
	}
}

func GenerateVDFIteration(seed, x_blob []byte, iterations, int_size_bits uint32) ([]byte, []byte) {
	int_size := (int_size_bits + 16) >> 4
	D := iqc.CreateDiscriminant(seed, int_size_bits)
	x, _ := iqc.NewClassGroupFromBytesDiscriminant(x_blob[:(2*int_size)], D)

	y, proof := calculateVDF(D, x, iterations, int_size_bits, nil)

	if (y == nil) || (proof == nil) {
		return nil, nil
	} else {
		return y.Serialize(), proof.Serialize()
	}
}

func VerifyVDF(seed, proof_blob []byte, iterations, int_size_bits uint32) bool {
	int_size := (int_size_bits + 16) >> 4

	D := iqc.CreateDiscriminant(seed, int_size_bits)
	x := iqc.NewClassGroupFromAbDiscriminant(big.NewInt(2), big.NewInt(1), D)
	y, _ := iqc.NewClassGroupFromBytesDiscriminant(proof_blob[:(2*int_size)], D)
	proof, _ := iqc.NewClassGroupFromBytesDiscriminant(proof_blob[2*int_size:], D)

	return verifyProof(x, y, proof, iterations)
}

func VerifyVDFIteration(seed, x_blob, proof_blob []byte, iterations, int_size_bits uint32) bool {
	int_size := (int_size_bits + 16) >> 4
	D := iqc.CreateDiscriminant(seed, int_size_bits)
	x, _ := iqc.NewClassGroupFromBytesDiscriminant(x_blob[:(2*int_size)], D)
	y, _ := iqc.NewClassGroupFromBytesDiscriminant(proof_blob[:(2*int_size)], D)
	proof, _ := iqc.NewClassGroupFromBytesDiscriminant(proof_blob[2*int_size:], D)

	return verifyProof(x, y, proof, iterations)
}

// Creates a random prime based on input x, y, T
// Note – this differs from harmony-one's implementation, as the Fiat-Shamir
// transform requires _all_ public parameters be input, or else there is the
// potential to forge proofs of time for larger iterations modulo the prime
func hashPrime(x, y []byte, T uint32) *big.Int {
	var j uint64 = 0

	jBuf := make([]byte, 8)
	z := new(big.Int)
	for {
		binary.BigEndian.PutUint64(jBuf, j)
		s := append([]byte("prime"), jBuf...)
		s = append(s, x...)
		s = append(s, y...)
		s = binary.BigEndian.AppendUint32(s, T)

		checkSum := sha256.Sum256(s[:])
		z.SetBytes(checkSum[:16])

		if z.ProbablyPrime(1) {
			return z
		}
		j++

	}
}

// Get's the ith block of  2^T // B
// such that sum(get_block(i) * 2^ki) = t^T // B
func getBlock(i, k, T int, B *big.Int) *big.Int {
	//(pow(2, k) * pow(2, T - k * (i + 1), B)) // B
	p1 := big.NewInt(int64(math.Pow(2, float64(k))))
	p2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(T-k*(i+1))), B)
	return iqc.FloorDivision(new(big.Int).Mul(p1, p2), B)
}

// Optimized evalutation of h ^ (2^T // B)
func evalOptimized(identity, h *iqc.ClassGroup, B *big.Int, T uint32, k, l int, C map[int]*iqc.ClassGroup) *iqc.ClassGroup {
	//k1 = k//2
	var k1 int = k / 2
	k0 := k - k1

	//x = identity
	x := identity.Clone()

	for j := l - 1; j > -1; j-- {
		//x = pow(x, pow(2, k))
		b_limit := int64(math.Pow(2, float64(k)))
		x = x.Pow(b_limit)
		if x == nil {
			return nil
		}

		//ys = {}
		ys := make([]*iqc.ClassGroup, b_limit)
		for b := int64(0); b < b_limit; b++ {
			ys[b] = identity
		}

		//for i in range(0, math.ceil((T)/(k*l))):
		for i := 0; i < int(math.Ceil(float64(T)/float64(k*l))); i++ {
			if int(T)-k*(i*l+j+1) < 0 {
				continue
			}

			///TODO: carefully check big.Int to int64 value conversion...might cause serious issues later
			b := getBlock(i*l+j, k, int(T), B).Int64()
			ys[b] = ys[b].Multiply(C[i*k*l])
			if ys[b] == nil {
				return nil
			}
		}

		//for b1 in range(0, pow(2, k1)):
		for b1 := 0; b1 < int(math.Pow(float64(2), float64(k1))); b1++ {
			z := identity
			//for b0 in range(0, pow(2, k0)):
			for b0 := 0; b0 < int(math.Pow(float64(2), float64((k0)))); b0++ {
				//z *= ys[b1 * pow(2, k0) + b0]
				z = z.Multiply(ys[int64(b1)*int64(math.Pow(float64(2), float64(k0)))+int64(b0)])
				if z == nil {
					return nil
				}
			}

			//x *= pow(z, b1 * pow(2, k0))
			c := z.Pow(int64(b1) * int64(math.Pow(float64(2), float64(k0))))
			if c == nil {
				return nil
			}
			x = x.Multiply(c)
			if x == nil {
				return nil
			}
		}

		//for b0 in range(0, pow(2, k0)):
		for b0 := 0; b0 < int(math.Pow(float64(2), float64(k0))); b0++ {
			z := identity
			//for b1 in range(0, pow(2, k1)):
			for b1 := 0; b1 < int(math.Pow(float64(2), float64(k1))); b1++ {
				//z *= ys[b1 * pow(2, k0) + b0]
				z = z.Multiply(ys[int64(b1)*int64(math.Pow(float64(2), float64(k0)))+int64(b0)])
				if z == nil {
					return nil
				}
			}
			//x *= pow(z, b0)
			d := z.Pow(int64(b0))
			if d == nil {
				return nil
			}
			x = x.Multiply(d)
			if x == nil {
				return nil
			}
		}
	}

	return x
}

// generate y = x ^ (2 ^T) and pi
func generateProof(identity, x, y *iqc.ClassGroup, T uint32, k, l int, powers map[int]*iqc.ClassGroup) *iqc.ClassGroup {
	//x_s = x.serialize()
	x_s := x.Serialize()

	//y_s = y.serialize()
	y_s := y.Serialize()

	B := hashPrime(x_s, y_s, T)

	proof := evalOptimized(identity, x, B, T, k, l, powers)

	return proof
}

func calculateVDF(discriminant *big.Int, x *iqc.ClassGroup, iterations, int_size_bits uint32, stop <-chan struct{}) (y, proof *iqc.ClassGroup) {
	L, k, _ := approximateParameters(iterations)
	loopCount := int(math.Ceil(float64(iterations) / float64(k*L)))
	// NB: Dusk needs to do the disjoint set arithmetic, marking this spot down
	// as the insertion point
	powers_to_calculate := make([]int, loopCount+2)

	// link into next
	for i := 0; i < loopCount+1; i++ {
		powers_to_calculate[i] = i * k * L
	}

	powers_to_calculate[loopCount+1] = int(iterations)

	powers := iterateSquarings(x, powers_to_calculate, stop)

	if powers == nil {
		return nil, nil
	}

	y = powers[int(iterations)]

	identity := iqc.IdentityForDiscriminant(discriminant)

	proof = generateProof(identity, x, y, iterations, k, L, powers)

	return y, proof
}

func verifyProof(x, y, proof *iqc.ClassGroup, T uint32) bool {
	//x_s = x.serialize()
	x_s := x.Serialize()

	//y_s = y.serialize()
	y_s := y.Serialize()

	B := hashPrime(x_s, y_s, T)

	r := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(T)), B)

	piB := proof.BigPow(B)
	if piB == nil {
		return false
	}

	xR := x.BigPow(r)
	if xR == nil {
		return false
	}

	z := piB.Multiply(xR)
	if (z != nil) && (z.Equal(y)) {
		return true
	} else {
		return false
	}
}
