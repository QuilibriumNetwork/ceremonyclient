package p2p

import (
	"fmt"
	"math/big"
	"sort"

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

// GetBloomFilter returns a bloom filter based on the data, however
// it assumes bitLength is a multiple of 32. If the filter size is not
// conformant, this will generate biased indices.
func GetBloomFilter(data []byte, bitLength int, k int) []byte {
	size := big.NewInt(int64(bitLength)).BitLen() - 1
	digest := sha3.Sum256(data)
	output := make([]byte, bitLength/8)
	outputBI := big.NewInt(0)
	digestBI := new(big.Int).SetBytes(digest[:])
	for i := 0; i < k; i++ {
		position := uint(0)
		for j := size * i; j < size*(i+1); j++ {
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

// GetBloomFilterIndices returns the indices of a bloom filter, in increasing
// order, assuming bitLength is a multiple of 32 as in GetBloomFilter.
func GetBloomFilterIndices(data []byte, bitLength int, k int) []byte {
	size := big.NewInt(int64(bitLength)).BitLen() - 1
	h := sha3.NewShake256()
	_, err := h.Write(data)
	if err != nil {
		panic(err)
	}

	digest := make([]byte, size*k/8)
	_, err = h.Read(digest)
	if err != nil {
		panic(err)
	}

	indices := []string{}
	for i := 0; i < k; i++ {
		position := make([]byte, size/8)
		for j := (size / 8) * i; j < (size/8)*(i+1); j++ {
			position[j%(size/8)] = digest[j]
		}
		found := false
		for _, ext := range indices {
			if ext == string(position) {
				k++
				found = true
				break
			}
		}
		if !found {
			p := sort.SearchStrings(indices, string(position))
			if len(indices) > p {
				indices = append(indices[:p+1], indices[p:]...)
				indices[p] = string(position)
			} else {
				indices = append(indices, string(position))
			}
		}
	}

	output := ""
	for _, idx := range indices {
		output += idx
	}
	return []byte(output)
}
