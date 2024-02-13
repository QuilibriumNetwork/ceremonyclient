package shuffle

import (
	"crypto/rand"
	"math/big"

	"filippo.io/edwards25519"
)

var lBE = []byte{
	16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 222, 249, 222, 162, 247,
	156, 214, 88, 18, 99, 26, 92, 245, 211, 236,
}
var lBigInt = big.NewInt(0).SetBytes(lBE)

func genPolyFrags(
	secret *edwards25519.Scalar,
	total, threshold int,
) []*edwards25519.Scalar {
	coeffs := []*edwards25519.Scalar{}
	coeffs = append(coeffs, secret)

	for i := 1; i < threshold; i++ {
		coeffBI, _ := rand.Int(rand.Reader, lBigInt)
		coeff := BigIntToLEBytes(coeffBI)
		scalar, err := edwards25519.NewScalar().SetCanonicalBytes(coeff[:])
		if err != nil {
			panic(err)
		}

		coeffs = append(coeffs, scalar)
	}

	frags := []*edwards25519.Scalar{}

	for i := 1; i <= total; i++ {
		result, _ := edwards25519.NewScalar().SetCanonicalBytes(coeffs[0].Bytes())
		iBytes := BigIntToLEBytes(big.NewInt(int64(i)))
		x, err := edwards25519.NewScalar().SetCanonicalBytes(iBytes)
		if err != nil {
			panic(err)
		}

		for j := 1; j <= threshold-1; j++ {
			xi := edwards25519.NewScalar().Multiply(coeffs[j], x)
			result.Add(result, xi)
			xmul, _ := edwards25519.NewScalar().SetCanonicalBytes(iBytes)
			x.Multiply(x, xmul)
		}

		frags = append(frags, result)
	}

	return frags
}

func ShamirSplitMatrix(
	matrix [][]*edwards25519.Scalar,
	total, threshold int,
) [][][]*edwards25519.Scalar {
	shamirMatrix := make([][][]*edwards25519.Scalar, len(matrix))

	for x := 0; x < len(matrix); x++ {
		shamirMatrix[x] = make([][]*edwards25519.Scalar, len(matrix[0]))
		for y := 0; y < len(matrix[0]); y++ {
			shamirMatrix[x][y] = genPolyFrags(matrix[x][y], total, threshold)
		}
	}

	return shamirMatrix
}

func AddMatrices(matrices ...[][]*edwards25519.Scalar) [][]*edwards25519.Scalar {
	result := make([][]*edwards25519.Scalar, len(matrices[0]))

	for x := 0; x < len(matrices[0]); x++ {
		result[x] = make([]*edwards25519.Scalar, len(matrices[0][0]))

		for y := 0; y < len(matrices[0][0]); y++ {
			result[x][y] = edwards25519.NewScalar()

			for i := 0; i < len(matrices); i++ {
				result[x][y].Add(result[x][y], matrices[i][x][y])
			}
		}
	}

	return result
}

func GenerateRandomVectorShares(
	length, total, threshold int,
) [][]*edwards25519.Scalar {
	result := make([][]*edwards25519.Scalar, length)

	for i := 0; i < length; i++ {
		bi, _ := rand.Int(rand.Reader, lBigInt)
		biBytes := BigIntToLEBytes(bi)
		scalar, _ := edwards25519.NewScalar().SetCanonicalBytes(biBytes[:])

		result[i] = genPolyFrags(scalar, total, threshold)
	}

	return result
}

func InterpolatePolynomialShares(
	shares []*edwards25519.Scalar,
	ids []int,
) *edwards25519.Scalar {
	var reconstructedSum *edwards25519.Scalar

	for j := 0; j < len(ids); j++ {
		oneLENumBytes := BigIntToLEBytes(big.NewInt(1))
		coeffNum, _ := edwards25519.NewScalar().SetCanonicalBytes(oneLENumBytes)
		coeffDenom, _ := edwards25519.NewScalar().SetCanonicalBytes(oneLENumBytes)

		for k := 0; k < len(ids); k++ {
			if j != k {
				ikBytes := BigIntToLEBytes(big.NewInt(int64(ids[k])))
				ijBytes := BigIntToLEBytes(big.NewInt(int64(ids[j])))
				ikScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(ikBytes)
				ijScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(ijBytes)

				coeffNum.Multiply(coeffNum, ikScalar)
				ikScalar.Subtract(ikScalar, ijScalar)
				coeffDenom.Multiply(coeffDenom, ikScalar)
			}
		}

		coeffDenom.Invert(coeffDenom)
		coeffNum.Multiply(coeffNum, coeffDenom)
		reconstructedFrag := edwards25519.NewScalar().Multiply(
			coeffNum,
			shares[ids[j]-1],
		)

		if reconstructedSum == nil {
			reconstructedSum = reconstructedFrag
		} else {
			reconstructedSum.Add(reconstructedSum, reconstructedFrag)
		}
	}

	return reconstructedSum
}

func LUDecompose(
	matrix [][]*edwards25519.Scalar,
) ([][]*edwards25519.Scalar, [][]*edwards25519.Scalar) {
	imax := 0
	maxA := edwards25519.NewScalar()
	N := len(matrix)
	p := make([]int, N)
	pm := make([][]*edwards25519.Scalar, N)
	newA := make([][]*edwards25519.Scalar, N)

	for i := 0; i < N; i++ {
		newA[i] = make([]*edwards25519.Scalar, N)
		pm[i] = make([]*edwards25519.Scalar, N)
		p[i] = i
		for j := 0; j < N; j++ {
			newA[i][j], _ = edwards25519.NewScalar().SetCanonicalBytes(
				matrix[i][j].Bytes(),
			)
		}
	}

	scalarOne, _ := edwards25519.NewScalar().SetCanonicalBytes(
		BigIntToLEBytes(big.NewInt(int64(1))),
	)

	for i := 0; i < N; i++ {
		maxA = edwards25519.NewScalar()
		imax = i

		for k := i; k < N; k++ {
			if LEBytesToBigInt(newA[k][i].Bytes()).Cmp(
				LEBytesToBigInt(maxA.Bytes()),
			) > 0 {
				maxA = newA[k][i]
				imax = k
			}
		}

		if imax != i {
			//pivoting P
			j := p[i]
			p[i] = p[imax]
			p[imax] = j

			//pivoting rows of A
			ptr := newA[i]
			newA[i] = newA[imax]
			newA[imax] = ptr
		}

		for j := i + 1; j < N; j++ {
			newA[j][i].Multiply(
				newA[j][i],
				edwards25519.NewScalar().Invert(newA[i][i]),
			)

			for k := i + 1; k < N; k++ {
				newA[j][k].Subtract(newA[j][k], edwards25519.NewScalar().Multiply(
					newA[j][i],
					newA[i][k],
				))
			}
		}
	}

	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			if p[i] == j {
				pm[i][j] = scalarOne
			} else {
				pm[i][j] = edwards25519.NewScalar()
			}
		}
	}

	return newA, pm
}

func Invert(matrix [][]*edwards25519.Scalar) [][]*edwards25519.Scalar {
	a, p := LUDecompose(matrix)
	ia := make([][]*edwards25519.Scalar, len(matrix))

	for i := 0; i < len(matrix); i++ {
		ia[i] = make([]*edwards25519.Scalar, len(matrix))
	}

	for j := 0; j < len(matrix); j++ {
		for i := 0; i < len(matrix); i++ {
			ia[i][j] = edwards25519.NewScalar().Set(p[i][j])

			for k := 0; k < i; k++ {
				ia[i][j].Subtract(ia[i][j], edwards25519.NewScalar().Multiply(
					a[i][k],
					ia[k][j],
				))
			}
		}

		for i := len(matrix) - 1; i >= 0; i-- {
			for k := i + 1; k < len(matrix); k++ {
				ia[i][j].Subtract(ia[i][j], edwards25519.NewScalar().Multiply(
					a[i][k],
					ia[k][j],
				))
			}

			ia[i][j].Multiply(ia[i][j], edwards25519.NewScalar().Invert(a[i][i]))
		}
	}

	return ia
}

func InterpolateMatrixShares(
	matrixShares [][][]*edwards25519.Scalar,
	ids []int,
) [][]*edwards25519.Scalar {
	matrix := make([][]*edwards25519.Scalar, len(matrixShares))

	for x := 0; x < len(matrix); x++ {
		matrix[x] = make([]*edwards25519.Scalar, len(matrixShares[0]))
		for y := 0; y < len(matrix[0]); y++ {
			matrix[x][y] = InterpolatePolynomialShares(matrixShares[x][y], ids)
		}
	}

	return matrix
}

func ScalarMult(a int, b [][]*edwards25519.Scalar) [][]*edwards25519.Scalar {
	prod := make([][]*edwards25519.Scalar, len(b))
	for x := 0; x < len(b); x++ {
		prod[x] = make([]*edwards25519.Scalar, len(b[0]))

		for y := 0; y < len(b[0]); y++ {
			if a >= 0 {
				prod[x][y], _ = edwards25519.NewScalar().SetCanonicalBytes(
					BigIntToLEBytes(big.NewInt(int64(a))),
				)
			} else {
				negA, _ := edwards25519.NewScalar().SetCanonicalBytes(
					BigIntToLEBytes(big.NewInt(int64(-a))),
				)
				prod[x][y] = edwards25519.NewScalar().Subtract(
					edwards25519.NewScalar(),
					negA,
				)
			}

			prod[x][y] = prod[x][y].Multiply(prod[x][y], b[x][y])
		}
	}

	return prod
}

func GenerateDotProduct(
	a, b [][]*edwards25519.Scalar,
) [][]*edwards25519.Scalar {
	if len(a[0]) != len(b) {
		panic("cannot generate dot product of a and b - mismatched length")
	}

	abMatrix := make([][]*edwards25519.Scalar, len(a))

	for x := 0; x < len(a); x++ {
		abMatrix[x] = make([]*edwards25519.Scalar, len(b[0]))

		for y := 0; y < len(b[0]); y++ {
			abMatrix[x][y] = edwards25519.NewScalar()

			for ay := 0; ay < len(a[0]); ay++ {
				abMatrix[x][y].MultiplyAdd(a[x][ay], b[ay][y], abMatrix[x][y])
			}
		}
	}

	return abMatrix
}

func GenerateRandomMatrixAndInverseShares(
	size, total, threshold int,
) [2][][][]*edwards25519.Scalar {
	output := make([][]*edwards25519.Scalar, size)
	for x := 0; x < size; x++ {
		output[x] = make([]*edwards25519.Scalar, size)
		for y := 0; y < size; y++ {
			i, _ := rand.Int(rand.Reader, lBigInt)
			iBytes := BigIntToLEBytes(i)
			iScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(iBytes[:])
			output[x][y] = iScalar
		}
	}

	splitOutput := ShamirSplitMatrix(output, total, threshold)
	splitInverse := ShamirSplitMatrix(Invert(output), total, threshold)

	return [2][][][]*edwards25519.Scalar{splitOutput, splitInverse}
}

func GenerateRandomBeaverTripleMatrixShares(
	size, total, threshold int,
) [3][][][]*edwards25519.Scalar {
	uMatrix := make([][]*edwards25519.Scalar, size)
	vMatrix := make([][]*edwards25519.Scalar, size)

	for i := 0; i < size; i++ {
		uMatrix[i] = make([]*edwards25519.Scalar, size)
		vMatrix[i] = make([]*edwards25519.Scalar, size)

		for j := 0; j < size; j++ {
			uj, _ := rand.Int(rand.Reader, lBigInt)
			ujBytes := BigIntToLEBytes(uj)
			ujScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(ujBytes[:])
			vj, _ := rand.Int(rand.Reader, lBigInt)
			vjBytes := BigIntToLEBytes(vj)
			vjScalar, _ := edwards25519.NewScalar().SetCanonicalBytes(vjBytes[:])

			uMatrix[i][j] = ujScalar
			vMatrix[i][j] = vjScalar
		}
	}

	uvMatrix := GenerateDotProduct(uMatrix, vMatrix)

	uMatrixShares := ShamirSplitMatrix(uMatrix, total, threshold)
	vMatrixShares := ShamirSplitMatrix(vMatrix, total, threshold)
	uvMatrixShares := ShamirSplitMatrix(uvMatrix, total, threshold)

	return [3][][][]*edwards25519.Scalar{
		uMatrixShares, vMatrixShares, uvMatrixShares,
	}
}

func GeneratePermutationMatrix(size int) [][]*edwards25519.Scalar {
	matrix := [][]*edwards25519.Scalar{}
	elements := []int{}

	for i := 0; i < size; i++ {
		elements = append(elements, i)
	}

	for i := 0; i < size; i++ {
		pos, _ := rand.Int(rand.Reader, big.NewInt(int64(len(elements))))
		var vecPos int

		elements, vecPos = remove(elements, int(pos.Int64()))

		scalarOne, err := edwards25519.NewScalar().SetCanonicalBytes(
			BigIntToLEBytes(big.NewInt(1)),
		)
		if err != nil {
			panic(err)
		}

		vector := []*edwards25519.Scalar{}

		for j := 0; j < vecPos; j++ {
			scalarZero, err := edwards25519.NewScalar().SetCanonicalBytes(
				BigIntToLEBytes(big.NewInt(0)),
			)
			if err != nil {
				panic(err)
			}

			vector = append(vector, scalarZero)
		}

		vector = append(vector, scalarOne)

		for j := vecPos + 1; j < size; j++ {
			scalarZero, err := edwards25519.NewScalar().SetCanonicalBytes(
				BigIntToLEBytes(big.NewInt(0)),
			)
			if err != nil {
				panic(err)
			}

			vector = append(vector, scalarZero)
		}

		matrix = append(matrix, vector)
	}

	return matrix
}

func BigIntToLEBytes(bi *big.Int) []byte {
	b := bi.Bytes()
	last := len(b) - 1

	for i := 0; i < len(b)/2; i++ {
		b[i], b[last-i] = b[last-i], b[i]
	}

	for i := len(b); i < 32; i++ {
		b = append(b, 0x00)
	}

	return b
}

func LEBytesToBigInt(bytes []byte) *big.Int {
	b := make([]byte, len(bytes))
	last := len(b) - 1

	for i := 0; i < len(b)/2; i++ {
		b[i], b[last-i] = b[last-i], b[i]
	}

	res := big.NewInt(0)
	return res.SetBytes(b)
}

func remove(elements []int, i int) ([]int, int) {
	ret := elements[i]
	elements[i] = elements[len(elements)-1]
	newElements := []int{}
	newElements = append(newElements, elements[:len(elements)-1]...)
	return newElements, ret
}
