//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/internal"
)

func TestScalarEd448Random(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Scalar.Random(testRng())
	s, ok := sc.(*ScalarEd448)
	require.True(t, ok)
	expected := toGSc("3e3d89d4531a059a5e4fc4ba87d3ef5c94d7ca133d6087648b5442d1e15ffa038eab7b739c1d2ff034b474b62a1fe40c3f81841c1e807f1c")
	require.Equal(t, s.value[:], expected[:])
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := ed448.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarEd448)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarEd448Hash(t *testing.T) {
	var b [32]byte
	ed448 := ED448()
	sc := ed448.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarEd448)
	require.True(t, ok)
	expected := toGSc("0e0ecc2b5ecf781cc81c38024194380cf16d9afad07c98eb49b0835dd6ad3062221e124311ec7f7181568de7938df805d894f5fded465001")
	require.Equal(t, s.value[:], expected[:])
}

func TestScalarEd448Zero(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Scalar.Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarEd448One(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Scalar.One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarEd448New(t *testing.T) {
	ed448 := ED448()
	three := ed448.Scalar.New(3)
	require.True(t, three.IsOdd())
	four := ed448.Scalar.New(4)
	require.True(t, four.IsEven())
	neg1 := ed448.Scalar.New(-1)
	require.True(t, neg1.IsEven())
	neg2 := ed448.Scalar.New(-2)
	require.True(t, neg2.IsOdd())
}

func TestScalarEd448Square(t *testing.T) {
	ed448 := ED448()
	three := ed448.Scalar.New(3)
	nine := ed448.Scalar.New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarEd448Cube(t *testing.T) {
	ed448 := ED448()
	three := ed448.Scalar.New(3)
	twentySeven := ed448.Scalar.New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarEd448Double(t *testing.T) {
	ed448 := ED448()
	three := ed448.Scalar.New(3)
	six := ed448.Scalar.New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarEd448Neg(t *testing.T) {
	ed448 := ED448()
	one := ed448.Scalar.One()
	neg1 := ed448.Scalar.New(-1)
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := ed448.Scalar.New(333333)
	expected := ed448.Scalar.New(-333333)
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarEd448Invert(t *testing.T) {
	ed448 := ED448()
	nine := ed448.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarEd448)
	expected := toGSc("c042bf42c31643f7d9dd346bb116e767a573937d0c08ba1710db5345e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23")
	require.Equal(t, sa.value[:], expected[:])
	require.Equal(t, nine.Mul(actual).(*ScalarEd448).value[:], ed448.Scalar.New(1).(*ScalarEd448).value[:])
}

func TestScalarEd448Add(t *testing.T) {
	ed448 := ED448()
	nine := ed448.Scalar.New(9)
	six := ed448.Scalar.New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := ed448.Scalar.New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)

	upper := ed448.Scalar.New(-3)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarEd448Sub(t *testing.T) {
	ed448 := ED448()
	nine := ed448.Scalar.New(9)
	six := ed448.Scalar.New(6)
	expected := ed448.Scalar.New(-3)

	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(ed448.Scalar.New(3)), 0)
}

func TestScalarEd448Mul(t *testing.T) {
	ed448 := ED448()
	nine := ed448.Scalar.New(9)
	six := ed448.Scalar.New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(ed448.Scalar.New(54)), 0)

	upper := ed448.Scalar.New(-1)
	require.Equal(t, upper.Mul(upper).Cmp(ed448.Scalar.New(1)), 0)
}

func TestScalarEd448Div(t *testing.T) {
	ed448 := ED448()
	nine := ed448.Scalar.New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(ed448.Scalar.New(1)), 0)
	require.Equal(t, ed448.Scalar.New(54).Div(nine).Cmp(ed448.Scalar.New(6)), 0)
}

func TestScalarEd448Serialize(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Scalar.New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 56)
	require.Equal(t, sequence, []byte{
		0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	})
	ret, err := ed448.Scalar.SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = ed448.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 56)
		ret, err = ed448.Scalar.SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarEd448Nil(t *testing.T) {
	ed448 := ED448()
	one := ed448.Scalar.New(1)
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, one.Div(nil))
	require.Nil(t, ed448.Scalar.Random(nil))
	require.Equal(t, one.Cmp(nil), -2)
	_, err := ed448.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointEd448Random(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Point.Random(testRng())
	s, ok := sc.(*PointEd448)
	require.True(t, ok)
	fmt.Println(hex.EncodeToString(s.ToAffineCompressed()))
	expected := toGPt("77ad569bd49c8a7228896c7e9c6a1af8f24912256f7fb0cce3de269932c5d64a3d2381bec8be6820a4ecfa4103d002ab8b5750b4beb1736400")
	require.True(t, s.Equal(&PointEd448{expected}))
	// Try 25 random values
	for i := 0; i < 25; i++ {
		sc := ed448.Point.Random(crand.Reader)
		_, ok := sc.(*PointEd448)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
		pBytes := sc.ToAffineCompressed()
		_, err := goldilocks.FromBytes(pBytes)
		require.NoError(t, err)
	}
}

func TestPointEd448Hash(t *testing.T) {
	var b [114]byte
	ed448 := ED448()
	sc := ed448.Point.Hash(b[:])
	s, ok := sc.(*PointEd448)
	require.True(t, ok)
	expected := toGPt("65458b113e6a77dbdfd75726961167cce206ac30022caf9153fb4754301943d3c58a95332b8119240905a551e18310e8f0dfc66d3cd0cb7700")
	require.True(t, s.Equal(&PointEd448{expected}))

	// Fuzz test
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(b[:])
		sc = ed448.Point.Hash(b[:])
		require.NotNil(t, sc)
	}
}

func TestPointEd448Identity(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{
		0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
}

func TestPointEd448Generator(t *testing.T) {
	ed448 := ED448()
	sc := ed448.Point.Generator()
	s, ok := sc.(*PointEd448)
	require.True(t, ok)
	require.Equal(t, s.ToAffineCompressed(), []byte{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
		0x0})
}

func TestPointEd448Set(t *testing.T) {
	ed448 := ED448()
	iden, err := ed448.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	xBytes, _ := hex.DecodeString("a913f565d4ddd5560df211dcf06ffa25297cb3ce3ae4495f6dff0d6486e7d319bf2ce0ef040cafaf8a3a7d9bc6c91bd2492897d0dd1012a8")
	yBytes, _ := hex.DecodeString("a9a0d4631f1cab9a00824d28670704b02f912470adbed436de82bc89b87b97c99e1ff55ae1afa8e377ced6a47ef6cd895f0b3588089fa1a6")
	x := new(big.Int).SetBytes(internal.ReverseScalarBytes(xBytes))
	y := new(big.Int).SetBytes(internal.ReverseScalarBytes(yBytes))
	newPoint, err := ed448.Point.Set(x, y)
	require.NoError(t, err)
	require.NotEqualf(t, iden, newPoint, "after setting valid x and y, the point should NOT be identity point")

	emptyX := new(big.Int).SetBytes(internal.ReverseScalarBytes([]byte{}))
	identityPoint, err := ed448.Point.Set(emptyX, y)
	require.NoError(t, err)
	require.Equalf(t, iden, identityPoint, "When x is empty, the point will be identity")
}

func TestPointEd448Double(t *testing.T) {
	ed448 := ED448()
	g := ed448.Point.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(ed448.Scalar.New(2))))
	i := ed448.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointEd448Neg(t *testing.T) {
	ed448 := ED448()
	g := ed448.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(ed448.Point.Generator()))
	require.True(t, ed448.Point.Identity().Neg().Equal(ed448.Point.Identity()))
}

func TestPointEd448Add(t *testing.T) {
	ed448 := ED448()
	pt := ed448.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(ed448.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointEd448Sub(t *testing.T) {
	ed448 := ED448()
	g := ed448.Point.Generator()
	pt := ed448.Point.Generator().Mul(ed448.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointEd448Mul(t *testing.T) {
	ed448 := ED448()
	g := ed448.Point.Generator()
	pt := ed448.Point.Generator().Mul(ed448.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointEd448Serialize(t *testing.T) {
	ed448 := ED448()
	ss := ed448.Scalar.Random(testRng())
	g := ed448.Point.Generator()

	ppt := g.Mul(ss)
	expectedC := []byte{
		0xe0, 0x75, 0x8a, 0x33, 0x26, 0x79, 0x39, 0xa3,
		0x94, 0xfb, 0x5c, 0xcb, 0x20, 0x2e, 0xe8, 0x51,
		0xce, 0xbc, 0x2e, 0x89, 0xc9, 0x1a, 0xc1, 0x28,
		0x9e, 0x2b, 0xfc, 0xdd, 0xfd, 0x9f, 0xf9, 0xfc,
		0x56, 0x94, 0xb0, 0xf5, 0x69, 0xd7, 0xf7, 0xe9,
		0xda, 0x16, 0xe1, 0xcd, 0xe9, 0x30, 0x1b, 0x29,
		0xf4, 0x81, 0x28, 0xb3, 0xcb, 0xd1, 0x16, 0x85,
		0x80,
	}
	expectedU := []byte{
		0x95, 0xcd, 0x44, 0x60, 0xa4, 0x5d, 0x47, 0x87,
		0x44, 0x71, 0x93, 0xd5, 0xc5, 0x38, 0xcb, 0x8b,
		0xec, 0x3a, 0x86, 0xae, 0x1a, 0xba, 0xf9, 0x24,
		0xa8, 0x4b, 0x25, 0x20, 0x47, 0x4c, 0xa1, 0x6c,
		0xe0, 0x33, 0x8d, 0xaa, 0xda, 0x54, 0x1a, 0x57,
		0x56, 0x86, 0x22, 0xc7, 0xbf, 0x24, 0x74, 0x7c,
		0xed, 0xd3, 0x6a, 0xad, 0x08, 0xb7, 0x7e, 0xd8,
		0xe0, 0x75, 0x8a, 0x33, 0x26, 0x79, 0x39, 0xa3,
		0x94, 0xfb, 0x5c, 0xcb, 0x20, 0x2e, 0xe8, 0x51,
		0xce, 0xbc, 0x2e, 0x89, 0xc9, 0x1a, 0xc1, 0x28,
		0x9e, 0x2b, 0xfc, 0xdd, 0xfd, 0x9f, 0xf9, 0xfc,
		0x56, 0x94, 0xb0, 0xf5, 0x69, 0xd7, 0xf7, 0xe9,
		0xda, 0x16, 0xe1, 0xcd, 0xe9, 0x30, 0x1b, 0x29,
		0xf4, 0x81, 0x28, 0xb3, 0xcb, 0xd1, 0x16, 0x85,
	}
	require.Equal(t, ppt.ToAffineCompressed(), expectedC)
	require.Equal(t, ppt.ToAffineUncompressed(), expectedU)
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := ed448.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 57)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 112)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointEd448Nil(t *testing.T) {
	ed448 := ED448()
	one := ed448.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, ed448.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := ed448.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointEd448SumOfProducts(t *testing.T) {
	lhs := new(PointEd448).Generator().Mul(new(ScalarEd448).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointEd448).Generator()
	}
	scalars := []Scalar{
		new(ScalarEd448).New(8),
		new(ScalarEd448).New(9),
		new(ScalarEd448).New(10),
		new(ScalarEd448).New(11),
		new(ScalarEd448).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}

func toGSc(hx string) *goldilocks.Scalar {
	e, _ := hex.DecodeString(hx)
	var data [56]byte
	copy(data[:], e)
	value := &goldilocks.Scalar{}
	value.FromBytes(data[:])
	return value
}

func toGPt(hx string) *goldilocks.Point {
	e, _ := hex.DecodeString(hx)
	var data [57]byte
	copy(data[:], e)
	pt, _ := new(PointEd448).FromAffineCompressed(data[:])
	return pt.(*PointEd448).value
}
