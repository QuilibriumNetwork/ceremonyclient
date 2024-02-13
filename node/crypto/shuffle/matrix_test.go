package shuffle_test

import (
	"fmt"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/shuffle"
)

func TestGeneratePermutationMatrix(t *testing.T) {
	m := shuffle.GeneratePermutationMatrix(6)
	for _, x := range m {
		ySum := byte(0x00)
		for _, y := range x {
			ySum += y.Bytes()[0]
		}

		assert.Equal(t, ySum, byte(0x01))
	}

	for x := 0; x < len(m); x++ {
		xSum := byte(0x00)

		for y := 0; y < len(m); y++ {
			xSum += m[y][x].Bytes()[0]
		}

		assert.Equal(t, xSum, byte(0x01))
	}
}

func verifyLagrange(t *testing.T, shares []*edwards25519.Scalar, expected *edwards25519.Scalar, total, threshold int) {
	var result *edwards25519.Scalar

	for i := 1; i <= total-threshold+1; i++ {
		var reconstructedSum *edwards25519.Scalar

		for j := 0; j < threshold; j++ {
			oneLENumBytes := shuffle.BigIntToLEBytes(big.NewInt(1))
			coeffNum, _ := edwards25519.NewScalar().SetCanonicalBytes(oneLENumBytes)
			coeffDenom, _ := edwards25519.NewScalar().SetCanonicalBytes(oneLENumBytes)

			for k := 0; k < threshold; k++ {
				if j != k {
					ikBytes := shuffle.BigIntToLEBytes(big.NewInt(int64(i + k)))
					ijBytes := shuffle.BigIntToLEBytes(big.NewInt(int64(i + j)))
					ikScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(ikBytes)
					ijScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(ijBytes)

					coeffNum.Multiply(coeffNum, ikScalar)
					ikScalar.Subtract(ikScalar, ijScalar)
					coeffDenom.Multiply(coeffDenom, ikScalar)
				}
			}

			coeffDenom.Invert(coeffDenom)
			coeffNum.Multiply(coeffNum, coeffDenom)
			reconstructedFrag := edwards25519.NewScalar().Multiply(coeffNum, shares[i+j-1])

			if reconstructedSum == nil {
				reconstructedSum = reconstructedFrag
			} else {
				reconstructedSum.Add(reconstructedSum, reconstructedFrag)
			}
		}

		if result == nil {
			result = reconstructedSum
			assert.Equal(t, expected.Bytes(), result.Bytes())
		} else if result.Equal(reconstructedSum) == 0 {
			fmt.Println("mismatched reconstruction")
			t.FailNow()
		}
	}
}

func TestGenerateShamirMatrix(t *testing.T) {
	m := shuffle.GeneratePermutationMatrix(6)
	sm := shuffle.ShamirSplitMatrix(m, 10, 3)
	for xi, x := range sm {
		for yi, y := range x {
			verifyLagrange(t, y, m[xi][yi], 10, 3)
		}
	}
}

func TestMatrixDotProduct(t *testing.T) {
	zeroBytes := shuffle.BigIntToLEBytes(big.NewInt(0))
	oneBytes := shuffle.BigIntToLEBytes(big.NewInt(1))
	twoBytes := shuffle.BigIntToLEBytes(big.NewInt(2))
	threeBytes := shuffle.BigIntToLEBytes(big.NewInt(3))
	fourBytes := shuffle.BigIntToLEBytes(big.NewInt(4))

	zero, _ := edwards25519.NewScalar().SetCanonicalBytes(zeroBytes)
	one, _ := edwards25519.NewScalar().SetCanonicalBytes(oneBytes)
	two, _ := edwards25519.NewScalar().SetCanonicalBytes(twoBytes)
	three, _ := edwards25519.NewScalar().SetCanonicalBytes(threeBytes)
	four, _ := edwards25519.NewScalar().SetCanonicalBytes(fourBytes)

	aMatrix := [][]*edwards25519.Scalar{
		{two, two},
		{zero, three},
		{zero, four},
	}
	bMatrix := [][]*edwards25519.Scalar{
		{two, one, two},
		{three, two, four},
	}

	abMatrix := shuffle.GenerateDotProduct(aMatrix, bMatrix)
	assert.Equal(t, byte(0x0a), abMatrix[0][0].Bytes()[0])
	assert.Equal(t, byte(0x06), abMatrix[0][1].Bytes()[0])
	assert.Equal(t, byte(0x0c), abMatrix[0][2].Bytes()[0])
	assert.Equal(t, byte(0x09), abMatrix[1][0].Bytes()[0])
	assert.Equal(t, byte(0x06), abMatrix[1][1].Bytes()[0])
	assert.Equal(t, byte(0x0c), abMatrix[1][2].Bytes()[0])
	assert.Equal(t, byte(0x0c), abMatrix[2][0].Bytes()[0])
	assert.Equal(t, byte(0x08), abMatrix[2][1].Bytes()[0])
	assert.Equal(t, byte(0x10), abMatrix[2][2].Bytes()[0])
}

func TestGenerateRandomBeaverTripleMatrixShares(t *testing.T) {
	beaverTripleShares := shuffle.GenerateRandomBeaverTripleMatrixShares(6, 10, 3)

	uMatrixShares := beaverTripleShares[0]
	vMatrixShares := beaverTripleShares[1]
	uvMatrixShares := beaverTripleShares[2]

	uMatrix := shuffle.InterpolateMatrixShares(uMatrixShares, []int{1, 2, 3})
	vMatrix := shuffle.InterpolateMatrixShares(vMatrixShares, []int{1, 2, 3})
	uvMatrix := shuffle.InterpolateMatrixShares(uvMatrixShares, []int{1, 2, 3})

	for x := 0; x < len(uMatrixShares); x++ {
		for y := 0; y < len(uMatrixShares[0]); y++ {
			verifyLagrange(t, uMatrixShares[x][y], uMatrix[x][y], 10, 3)
			verifyLagrange(t, vMatrixShares[x][y], vMatrix[x][y], 10, 3)
			verifyLagrange(t, uvMatrixShares[x][y], uvMatrix[x][y], 10, 3)
		}
	}

	uvCheck := shuffle.GenerateDotProduct(uMatrix, vMatrix)
	assert.Equal(t, uvMatrix, uvCheck)
}

func TestPermutationMatrix(t *testing.T) {
	permutationMatrix1 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix2 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix3 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix4 := shuffle.GeneratePermutationMatrix(6)

	permutationMatrix := shuffle.GenerateDotProduct(permutationMatrix1, permutationMatrix2)
	permutationMatrix = shuffle.GenerateDotProduct(permutationMatrix, permutationMatrix3)
	permutationMatrix = shuffle.GenerateDotProduct(permutationMatrix, permutationMatrix4)

	one, _ := edwards25519.NewScalar().SetCanonicalBytes(shuffle.BigIntToLEBytes(big.NewInt(1)))
	for x := 0; x < 6; x++ {
		sumX := edwards25519.NewScalar()

		for y := 0; y < 6; y++ {
			sumX.Add(sumX, permutationMatrix[x][y])
		}

		assert.Equal(t, sumX, one)
	}

	for y := 0; y < 6; y++ {
		sumY := edwards25519.NewScalar()

		for x := 0; x < 6; x++ {
			sumY.Add(sumY, permutationMatrix[x][y])
		}

		assert.Equal(t, sumY, one)
	}
}

func TestPermutationSharing(t *testing.T) {
	permutationMatrix1 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix2 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix3 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrix4 := shuffle.GeneratePermutationMatrix(6)
	permutationMatrixShares1 := shuffle.ShamirSplitMatrix(permutationMatrix1, 4, 3)
	permutationMatrixShares2 := shuffle.ShamirSplitMatrix(permutationMatrix2, 4, 3)
	permutationMatrixShares3 := shuffle.ShamirSplitMatrix(permutationMatrix3, 4, 3)
	permutationMatrixShares4 := shuffle.ShamirSplitMatrix(permutationMatrix4, 4, 3)

	inverseShareMatrix1 := make([][][]*edwards25519.Scalar, 4)
	inverseShareMatrix2 := make([][][]*edwards25519.Scalar, 4)
	inverseShareMatrix3 := make([][][]*edwards25519.Scalar, 4)
	inverseShareMatrix4 := make([][][]*edwards25519.Scalar, 4)

	for i := 0; i < 4; i++ {
		inverseShareMatrix1[i] = make([][]*edwards25519.Scalar, 6)
		inverseShareMatrix2[i] = make([][]*edwards25519.Scalar, 6)
		inverseShareMatrix3[i] = make([][]*edwards25519.Scalar, 6)
		inverseShareMatrix4[i] = make([][]*edwards25519.Scalar, 6)

		for x := 0; x < 6; x++ {
			inverseShareMatrix1[i][x] = make([]*edwards25519.Scalar, 6)
			inverseShareMatrix2[i][x] = make([]*edwards25519.Scalar, 6)
			inverseShareMatrix3[i][x] = make([]*edwards25519.Scalar, 6)
			inverseShareMatrix4[i][x] = make([]*edwards25519.Scalar, 6)

			for y := 0; y < 6; y++ {
				inverseShareMatrix1[i][x][y] = permutationMatrixShares1[x][y][i]
				inverseShareMatrix2[i][x][y] = permutationMatrixShares2[x][y][i]
				inverseShareMatrix3[i][x][y] = permutationMatrixShares3[x][y][i]
				inverseShareMatrix4[i][x][y] = permutationMatrixShares4[x][y][i]
			}
		}
	}

	beaverTripleShares1 := shuffle.GenerateRandomBeaverTripleMatrixShares(6, 4, 3)
	beaverTripleShares2 := shuffle.GenerateRandomBeaverTripleMatrixShares(6, 4, 3)
	beaverTripleShares3 := shuffle.GenerateRandomBeaverTripleMatrixShares(6, 4, 3)

	beaverTriplesAShares1 := beaverTripleShares1[0]
	beaverTriplesBShares1 := beaverTripleShares1[1]
	beaverTriplesABShares1 := beaverTripleShares1[2]
	beaverTriplesAShares2 := beaverTripleShares2[0]
	beaverTriplesBShares2 := beaverTripleShares2[1]
	beaverTriplesABShares2 := beaverTripleShares2[2]
	beaverTriplesAShares3 := beaverTripleShares3[0]
	beaverTriplesBShares3 := beaverTripleShares3[1]
	beaverTriplesABShares3 := beaverTripleShares3[2]

	inverseBeaverTriplesAShares1 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesBShares1 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesABShares1 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesAShares2 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesBShares2 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesABShares2 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesAShares3 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesBShares3 := make([][][]*edwards25519.Scalar, 4)
	inverseBeaverTriplesABShares3 := make([][][]*edwards25519.Scalar, 4)

	for i := 0; i < 4; i++ {
		inverseBeaverTriplesAShares1[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesBShares1[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesABShares1[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesAShares2[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesBShares2[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesABShares2[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesAShares3[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesBShares3[i] = make([][]*edwards25519.Scalar, 6)
		inverseBeaverTriplesABShares3[i] = make([][]*edwards25519.Scalar, 6)

		for x := 0; x < 6; x++ {
			inverseBeaverTriplesAShares1[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesBShares1[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesABShares1[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesAShares2[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesBShares2[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesABShares2[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesAShares3[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesBShares3[i][x] = make([]*edwards25519.Scalar, 6)
			inverseBeaverTriplesABShares3[i][x] = make([]*edwards25519.Scalar, 6)

			for y := 0; y < 6; y++ {
				inverseBeaverTriplesAShares1[i][x][y] = beaverTriplesAShares1[x][y][i]
				inverseBeaverTriplesBShares1[i][x][y] = beaverTriplesBShares1[x][y][i]
				inverseBeaverTriplesABShares1[i][x][y] = beaverTriplesABShares1[x][y][i]
				inverseBeaverTriplesAShares2[i][x][y] = beaverTriplesAShares2[x][y][i]
				inverseBeaverTriplesBShares2[i][x][y] = beaverTriplesBShares2[x][y][i]
				inverseBeaverTriplesABShares2[i][x][y] = beaverTriplesABShares2[x][y][i]
				inverseBeaverTriplesAShares3[i][x][y] = beaverTriplesAShares3[x][y][i]
				inverseBeaverTriplesBShares3[i][x][y] = beaverTriplesBShares3[x][y][i]
				inverseBeaverTriplesABShares3[i][x][y] = beaverTriplesABShares3[x][y][i]
			}
		}
	}

	es1 := make([][][]*edwards25519.Scalar, 6)
	fs1 := make([][][]*edwards25519.Scalar, 6)
	es2 := make([][][]*edwards25519.Scalar, 6)
	fs2 := make([][][]*edwards25519.Scalar, 6)
	es3 := make([][][]*edwards25519.Scalar, 6)
	fs3 := make([][][]*edwards25519.Scalar, 6)

	for x := 0; x < 6; x++ {
		es1[x] = make([][]*edwards25519.Scalar, 6)
		fs1[x] = make([][]*edwards25519.Scalar, 6)
		es2[x] = make([][]*edwards25519.Scalar, 6)
		fs2[x] = make([][]*edwards25519.Scalar, 6)
		es3[x] = make([][]*edwards25519.Scalar, 6)
		fs3[x] = make([][]*edwards25519.Scalar, 6)

		for y := 0; y < 6; y++ {
			es1[x][y] = make([]*edwards25519.Scalar, 4)
			fs1[x][y] = make([]*edwards25519.Scalar, 4)
			es2[x][y] = make([]*edwards25519.Scalar, 4)
			fs2[x][y] = make([]*edwards25519.Scalar, 4)
			es3[x][y] = make([]*edwards25519.Scalar, 4)
			fs3[x][y] = make([]*edwards25519.Scalar, 4)

			for i := 0; i < 4; i++ {
				es1[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix1[i][x][y], inverseBeaverTriplesAShares1[i][x][y])
				fs1[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix2[i][x][y], inverseBeaverTriplesBShares1[i][x][y])
				es2[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix2[i][x][y], inverseBeaverTriplesAShares2[i][x][y])
				fs2[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix3[i][x][y], inverseBeaverTriplesBShares2[i][x][y])
				es3[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix3[i][x][y], inverseBeaverTriplesAShares3[i][x][y])
				fs3[x][y][i] = edwards25519.NewScalar().Subtract(inverseShareMatrix4[i][x][y], inverseBeaverTriplesBShares3[i][x][y])
			}
		}
	}
	// e = a - u
	// f = b - v
	// (a - u)(b - v) = -ab + ub + av - uv + (ab-av) + (ab - ub) + uv

	e1 := shuffle.InterpolateMatrixShares(es1, []int{1, 2, 3, 4})
	f1 := shuffle.InterpolateMatrixShares(fs1, []int{1, 2, 3, 4})
	e2 := shuffle.InterpolateMatrixShares(es2, []int{1, 2, 3, 4})
	f2 := shuffle.InterpolateMatrixShares(fs2, []int{1, 2, 3, 4})
	e3 := shuffle.InterpolateMatrixShares(es3, []int{1, 2, 3, 4})
	f3 := shuffle.InterpolateMatrixShares(fs3, []int{1, 2, 3, 4})

	// mul(a, b) => <e> = <a> - <u>, <f> = <b> - <v>, <c> = -i * e * f + f * <a> + e * <b> + <z>

	ef1 := shuffle.GenerateDotProduct(e1, f1)
	ef2 := shuffle.GenerateDotProduct(e2, f2)
	ef3 := shuffle.GenerateDotProduct(e3, f3)
	fa1 := make([][][]*edwards25519.Scalar, 4)
	fa2 := make([][][]*edwards25519.Scalar, 4)
	fa3 := make([][][]*edwards25519.Scalar, 4)
	eb1 := make([][][]*edwards25519.Scalar, 4)
	eb2 := make([][][]*edwards25519.Scalar, 4)
	eb3 := make([][][]*edwards25519.Scalar, 4)
	cs1 := make([][][]*edwards25519.Scalar, 4)
	cs2 := make([][][]*edwards25519.Scalar, 4)
	cs3 := make([][][]*edwards25519.Scalar, 4)
	// cs := make([][][]*edwards25519.Scalar, 4)
	inverseCS1 := make([][][]*edwards25519.Scalar, 6)
	inverseCS3 := make([][][]*edwards25519.Scalar, 6)

	for i := 0; i < 4; i++ {
		fa1[i] = shuffle.GenerateDotProduct(inverseShareMatrix1[i], f1)
		eb1[i] = shuffle.GenerateDotProduct(e1, inverseShareMatrix2[i])
		fa2[i] = shuffle.GenerateDotProduct(inverseShareMatrix2[i], f2)
		eb2[i] = shuffle.GenerateDotProduct(e2, inverseShareMatrix3[i])
		fa3[i] = shuffle.GenerateDotProduct(inverseShareMatrix3[i], f3)
		eb3[i] = shuffle.GenerateDotProduct(e3, inverseShareMatrix4[i])
		cs1[i] = shuffle.AddMatrices(shuffle.ScalarMult(-1, ef1), fa1[i], eb1[i], inverseBeaverTriplesABShares1[i])
		cs2[i] = shuffle.AddMatrices(shuffle.ScalarMult(-1, ef2), fa2[i], eb2[i], inverseBeaverTriplesABShares2[i])
		cs3[i] = shuffle.AddMatrices(shuffle.ScalarMult(-1, ef3), fa3[i], eb3[i], inverseBeaverTriplesABShares3[i])
	}

	for x := 0; x < 6; x++ {
		inverseCS1[x] = make([][]*edwards25519.Scalar, 6)
		inverseCS3[x] = make([][]*edwards25519.Scalar, 6)
		for y := 0; y < 6; y++ {
			inverseCS1[x][y] = make([]*edwards25519.Scalar, 4)
			inverseCS3[x][y] = make([]*edwards25519.Scalar, 4)
			for i := 0; i < 4; i++ {
				inverseCS1[x][y][i] = cs1[i][x][y]
				inverseCS3[x][y][i] = cs3[i][x][y]
			}
		}
	}

	c1 := shuffle.InterpolateMatrixShares(inverseCS1, []int{1, 2, 3, 4})
	c3 := shuffle.InterpolateMatrixShares(inverseCS3, []int{1, 2, 3, 4})
	c := shuffle.GenerateDotProduct(c1, c3)
	ab := shuffle.GenerateDotProduct(permutationMatrix1, permutationMatrix2)
	abc := shuffle.GenerateDotProduct(ab, permutationMatrix3)
	abcd := shuffle.GenerateDotProduct(abc, permutationMatrix4)

	for x := 0; x < 6; x++ {
		for y := 0; y < 6; y++ {
			assert.ElementsMatch(t, c[x][y].Bytes(), abcd[x][y].Bytes())
		}
	}
}

// func TestIlanBeaverMultiMatrixSharing(t *testing.T) {
// 	fmt.Println("start")
// 	start := time.Now()
// 	ri := [65][][][]*edwards25519.Scalar{}
// 	rj := [65][][][]*edwards25519.Scalar{}

// 	next := time.Now()
// 	diff := next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("generating random and inverse matrices")
// 	var wg sync.WaitGroup

// 	for i := 0; i <= 64; i++ {
// 		wg.Add(1)

// 		i := i

// 		go func() {
// 			defer wg.Done()
// 			rs := crypto.GenerateRandomMatrixAndInverseShares(80, 4, 3)
// 			ri[i] = make([][][]*edwards25519.Scalar, 4)
// 			rj[i] = make([][][]*edwards25519.Scalar, 4)
// 			for j := 0; j < 4; j++ {
// 				ri[i][j] = make([][]*edwards25519.Scalar, 80)
// 				rj[i][j] = make([][]*edwards25519.Scalar, 80)
// 				for x := 0; x < 80; x++ {
// 					ri[i][j][x] = make([]*edwards25519.Scalar, 80)
// 					rj[i][j][x] = make([]*edwards25519.Scalar, 80)
// 					for y := 0; y < 80; y++ {
// 						ri[i][j][x][y] = rs[0][x][y][j]
// 						rj[i][j][x][y] = rs[1][x][y][j]
// 					}
// 				}
// 			}
// 		}()
// 	}

// 	wg.Wait()

// 	next = time.Now()
// 	diff = next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("generating permutation matrices")
// 	rxr := [64][][][]*edwards25519.Scalar{}

// 	for i := 1; i <= 64; i++ {
// 		wg.Add(1)

// 		i := i

// 		go func() {
// 			defer wg.Done()
// 			x := crypto.GeneratePermutationMatrix(80)
// 			xs := crypto.ShamirSplitMatrix(x, 4, 3)
// 			ixs := make([][][]*edwards25519.Scalar, 4)
// 			rxr[i-1] = make([][][]*edwards25519.Scalar, 4)
// 			for j := 0; j < 4; j++ {
// 				ixs[j] = make([][]*edwards25519.Scalar, 80)
// 				rxr[i-1][j] = make([][]*edwards25519.Scalar, 80)
// 				for x := 0; x < 80; x++ {
// 					ixs[j][x] = make([]*edwards25519.Scalar, 80)
// 					rxr[i-1][j][x] = make([]*edwards25519.Scalar, 80)
// 					for y := 0; y < 80; y++ {
// 						ixs[j][x][y] = xs[x][y][j]
// 					}
// 				}
// 			}
// 			for j := 0; j < 4; j++ {
// 				rxrij := crypto.GenerateDotProduct(ri[i-1][j], ixs[j])
// 				rxr[i-1][j] = crypto.GenerateDotProduct(rxrij, rj[i][j])
// 			}
// 		}()
// 	}

// 	wg.Wait()

// 	next = time.Now()
// 	diff = next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("swapping elements for interpolation")
// 	irxr := [64][][][]*edwards25519.Scalar{}
// 	for i := 0; i < 64; i++ {
// 		wg.Add(1)

// 		i := i

// 		go func() {
// 			defer wg.Done()
// 			irxr[i] = make([][][]*edwards25519.Scalar, 80)
// 			for x := 0; x < 80; x++ {
// 				irxr[i][x] = make([][]*edwards25519.Scalar, 80)
// 				for y := 0; y < 80; y++ {
// 					irxr[i][x][y] = make([]*edwards25519.Scalar, 4)
// 					for j := 0; j < 4; j++ {
// 						irxr[i][x][y][j] = rxr[i][j][x][y]
// 					}
// 				}
// 			}
// 		}()
// 	}

// 	wg.Wait()

// 	rxri := [][]*edwards25519.Scalar{}

// 	next = time.Now()
// 	diff = next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("interpolating")

// 	for i := 0; i < 64; i++ {
// 		next := crypto.InterpolateMatrixShares(irxr[i], []int{1, 2, 3})
// 		if i == 0 {
// 			rxri = next
// 		} else {
// 			rxri = crypto.GenerateDotProduct(rxri, next)
// 		}
// 	}

// 	rpms := make([][][]*edwards25519.Scalar, 4)
// 	next = time.Now()
// 	diff = next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("generating intermediary dot products")

// 	for i := 1; i <= 4; i++ {
// 		rpms[i-1] = crypto.GenerateDotProduct(crypto.GenerateDotProduct(rj[0][i-1], rxri), ri[64][i-1])
// 	}

// 	final := make([][][]*edwards25519.Scalar, 80)
// 	for x := 0; x < 80; x++ {
// 		final[x] = make([][]*edwards25519.Scalar, 80)
// 		for y := 0; y < 80; y++ {
// 			final[x][y] = make([]*edwards25519.Scalar, 4)
// 			for j := 0; j < 4; j++ {
// 				final[x][y][j] = rpms[j][x][y]
// 			}
// 		}
// 	}

// 	next = time.Now()
// 	diff = next.Sub(start)
// 	fmt.Println(diff)
// 	start = next
// 	fmt.Println("final interpolation")
// 	rpm := crypto.InterpolateMatrixShares(final, []int{1, 2, 3})

// 	for x := 0; x < 80; x++ {
// 		for y := 0; y < 80; y++ {
// 			fmt.Printf("%x, ", rpm[x][y].Bytes()[0])
// 		}
// 		fmt.Println()
// 	}
// 	t.Fail()
// }
