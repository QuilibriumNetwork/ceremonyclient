package p2p

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// getOnesIndices returns the indices of all bits that are 1 in the byte slice.
func getOnesIndices(input []byte) []int {
	var indices []int
	for i, b := range input {
		for j := 0; j < 8; j++ {
			if (b>>j)&1 == 1 {
				indices = append(indices, i*8+j)
			}
		}
	}
	return indices
}

// generateCombinations generates combinations of size k from the given slice.
func generateCombinations(arr []int, k int) [][]int {
	var ans [][]int
	if k == 0 {
		return [][]int{{}}
	}
	if len(arr) == 0 {
		return nil
	}
	head := arr[0]
	tail := arr[1:]
	// With head
	for _, sub := range generateCombinations(tail, k-1) {
		ans = append(ans, append([]int{head}, sub...))
	}
	// Without head
	ans = append(ans, generateCombinations(tail, k)...)
	return ans
}

// generateBitSlices returns byte slices with only three 1-bits, and evaluates
// the supplied function on the new byte slices.
func generateBitSlices(
	input []byte,
	eval func(slice []byte) error,
) error {
	oneIndices := getOnesIndices(input)
	combinations := generateCombinations(oneIndices, 3)

	for _, combo := range combinations {
		newSlice := make([]byte, len(input))
		for _, index := range combo {
			byteIndex := index / 8
			bitIndex := index % 8
			newSlice[byteIndex] |= (1 << bitIndex)
		}
		if err := eval(newSlice); err != nil {
			return err
		}
	}

	return nil
}

// getBloomFilterIndices returns a bloom filter index based on the data, however
// it assumes bitLength is a multiple of 32. If the filter size is not
// conformant, this will generate biased indices.
func getBloomFilterIndices(data []byte, bitLength int, k int) []byte {
	size := big.NewInt(int64(bitLength)).BitLen() - 1
	digest := sha3.Sum256(data)
	output := make([]byte, bitLength/8)
	outputBI := big.NewInt(0)
	digestBI := new(big.Int).SetBytes(digest[:])
	for i := 0; i < k; i++ {
		position := uint(0)
		for j := size*(i+1) - 1; j >= size*i; j-- {
			position = position<<1 | (digestBI.Bit(j))
		}
		if outputBI.Bit(int(position)) != 1 {
			outputBI.SetBit(outputBI, int(position), 1)
		} else if k*size <= 32 {
			// we need to extend the search
			k++
		} else {
			fmt.Printf(
				"digest %+x cannot be used as bloom index, panicking\n",
				digest,
			)
			panic(
				"could not generate bloom filter index, k offset cannot be adjusted",
			)
		}
	}
	outputBI.FillBytes(output)
	return output
}
