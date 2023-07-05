//
// Copyright (c) 2019 harmony-one
//
// SPDX-License-Identifier: MIT
//

package iqc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type Pair struct {
	p int64
	q int64
}

var m = 8 * 3 * 5 * 7 * 11 * 13

func EntropyFromSeed(seed []byte, byte_count uint32) []byte {
	buffer := bytes.Buffer{}
	bufferSize := uint32(0)

	extra := uint16(0)
	bytes := make([]byte, len(seed)+2)
	copy(bytes, seed)
	for bufferSize <= byte_count {
		binary.BigEndian.PutUint16(bytes[len(seed):], extra)
		more_entropy := sha256.Sum256(bytes)
		buffer.Write(more_entropy[:])
		bufferSize += sha256.Size
		extra += 1
	}

	return buffer.Bytes()[:byte_count]
}

//Return a discriminant of the given length using the given seed
//It is a random prime p between 13 - 2^2K
//return -p, where p % 8 == 7
func CreateDiscriminant(seed []byte, length uint32) *big.Int {
	extra := uint8(length) & 7
	byte_count := ((length + 7) >> 3) + 2
	entropy := EntropyFromSeed(seed, byte_count)

	n := new(big.Int)
	n.SetBytes(entropy[:len(entropy)-2])
	n = new(big.Int).Rsh(n, uint(((8 - extra) & 7)))
	n = new(big.Int).SetBit(n, int(length-1), 1)
	n = new(big.Int).Sub(n, new(big.Int).Mod(n, big.NewInt(int64(m))))
	n = new(big.Int).Add(n, big.NewInt(int64(residues[int(binary.BigEndian.Uint16(entropy[len(entropy)-2:]))%len(residues)])))

	negN := new(big.Int).Neg(n)

	// Find the smallest prime >= n of the form n + m*x
	for {
		sieve := make([]bool, (1 << 16))

		for _, v := range sieve_info {
			// q = m^-1 (mod p)
			// i = -n / m, so that m*i is -n (mod p)
			//i := ((-n % v.p) * v.q) % v.p
			i := (new(big.Int).Mod(negN, big.NewInt(v.p)).Int64() * v.q) % v.p

			for i < int64(len(sieve)) {
				sieve[i] = true
				i += v.p
			}
		}

		for i, v := range sieve {
			t := new(big.Int).Add(n, big.NewInt(int64(m)*int64(i)))
			if !v && t.ProbablyPrime(1) {
				return new(big.Int).Neg(t)
			}
		}

		//n += m * (1 << 16)
		bigM := big.NewInt(int64(m))
		n = new(big.Int).Add(n, bigM.Mul(bigM, big.NewInt(int64(1<<16))))

	}
}
