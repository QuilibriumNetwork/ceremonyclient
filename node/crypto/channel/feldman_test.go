package channel_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	crypto "source.quilibrium.com/quilibrium/monorepo/node/crypto/channel"
)

func TestFeldman(t *testing.T) {
	s1 := curves.ED25519().NewScalar().Random(rand.Reader)
	f1, err := crypto.NewFeldman(
		3,
		5,
		1,
		s1,
		*curves.ED25519(),
		curves.ED25519().NewGeneratorPoint(),
	)
	assert.NoError(t, err)

	s2 := curves.ED25519().NewScalar().Random(rand.Reader)
	f2, err := crypto.NewFeldman(
		3,
		5,
		2,
		s2,
		*curves.ED25519(),
		curves.ED25519().NewGeneratorPoint(),
	)
	assert.NoError(t, err)

	s3 := curves.ED25519().NewScalar().Random(rand.Reader)
	f3, err := crypto.NewFeldman(
		3,
		5,
		3,
		s3,
		*curves.ED25519(),
		curves.ED25519().NewGeneratorPoint(),
	)
	assert.NoError(t, err)

	s4 := curves.ED25519().NewScalar().Random(rand.Reader)
	f4, err := crypto.NewFeldman(
		3,
		5,
		4,
		s4,
		*curves.ED25519(),
		curves.ED25519().NewGeneratorPoint(),
	)
	assert.NoError(t, err)

	s5 := curves.ED25519().NewScalar().Random(rand.Reader)
	f5, err := crypto.NewFeldman(
		3,
		5,
		5,
		s5,
		*curves.ED25519(),
		curves.ED25519().NewGeneratorPoint(),
	)
	assert.NoError(t, err)

	err = f1.SamplePolynomial()
	assert.NoError(t, err)
	err = f2.SamplePolynomial()
	assert.NoError(t, err)
	err = f3.SamplePolynomial()
	assert.NoError(t, err)
	err = f4.SamplePolynomial()
	assert.NoError(t, err)
	err = f5.SamplePolynomial()
	assert.NoError(t, err)
	m1, err := f1.GetPolyFrags()
	assert.NoError(t, err)
	m2, err := f2.GetPolyFrags()
	assert.NoError(t, err)
	m3, err := f3.GetPolyFrags()
	assert.NoError(t, err)
	m4, err := f4.GetPolyFrags()
	assert.NoError(t, err)
	m5, err := f5.GetPolyFrags()
	assert.NoError(t, err)

	m1[1] = f1.Scalar().Bytes()

	_, err = f1.SetPolyFragForParty(2, m2[1])
	assert.NoError(t, err)
	_, err = f1.SetPolyFragForParty(3, m3[1])
	assert.NoError(t, err)
	_, err = f1.SetPolyFragForParty(4, m4[1])
	assert.NoError(t, err)
	z1, err := f1.SetPolyFragForParty(5, m5[1])
	assert.NoError(t, err)

	_, err = f2.SetPolyFragForParty(1, m1[2])
	assert.NoError(t, err)
	_, err = f2.SetPolyFragForParty(3, m3[2])
	assert.NoError(t, err)
	_, err = f2.SetPolyFragForParty(4, m4[2])
	assert.NoError(t, err)
	z2, err := f2.SetPolyFragForParty(5, m5[2])
	assert.NoError(t, err)

	_, err = f3.SetPolyFragForParty(1, m1[3])
	assert.NoError(t, err)
	_, err = f3.SetPolyFragForParty(2, m2[3])
	assert.NoError(t, err)
	_, err = f3.SetPolyFragForParty(4, m4[3])
	assert.NoError(t, err)
	z3, err := f3.SetPolyFragForParty(5, m5[3])
	assert.NoError(t, err)

	_, err = f4.SetPolyFragForParty(1, m1[4])
	assert.NoError(t, err)
	_, err = f4.SetPolyFragForParty(2, m2[4])
	assert.NoError(t, err)
	_, err = f4.SetPolyFragForParty(3, m3[4])
	assert.NoError(t, err)
	z4, err := f4.SetPolyFragForParty(5, m5[4])
	assert.NoError(t, err)

	_, err = f5.SetPolyFragForParty(1, m1[5])
	assert.NoError(t, err)
	_, err = f5.SetPolyFragForParty(2, m2[5])
	assert.NoError(t, err)
	_, err = f5.SetPolyFragForParty(3, m3[5])
	assert.NoError(t, err)
	z5, err := f5.SetPolyFragForParty(4, m4[5])
	assert.NoError(t, err)

	_, err = f1.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	assert.NoError(t, err)
	_, err = f1.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	assert.NoError(t, err)
	_, err = f1.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	assert.NoError(t, err)
	r1, err := f1.ReceiveCommitments(5, z5)
	assert.NoError(t, err)
	assert.NoError(t, err)

	_, err = f2.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f2.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	_, err = f2.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	r2, err := f2.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f3.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f3.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f3.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	r3, err := f3.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f4.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f4.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f4.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	r4, err := f4.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f5.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f5.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f5.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	r5, err := f5.ReceiveCommitments(4, z4)
	assert.NoError(t, err)

	_, err = f1.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f1.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f1.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f1.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f2.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f2.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f2.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f2.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f3.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f3.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f3.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f3.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f4.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f4.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f4.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f4.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f5.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f5.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f5.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f5.Recombine(4, r4)
	assert.NoError(t, err)

	s := s1.Add(s2.Add(s3.Add(s4.Add(s5))))
	assert.True(t, curves.ED25519().NewGeneratorPoint().Mul(s).Equal(f1.PublicKey()))
	assert.True(t, f5.PublicKey().Equal(f1.PublicKey()))
}

func TestFeldmanCustomGenerator(t *testing.T) {
	gen := curves.ED25519().Point.Random(rand.Reader)
	f1, err := crypto.NewFeldman(
		3,
		5,
		1,
		curves.ED25519().NewScalar().Random(rand.Reader),
		*curves.ED25519(),
		gen,
	)
	assert.NoError(t, err)

	f2, err := crypto.NewFeldman(
		3,
		5,
		2,
		curves.ED25519().NewScalar().Random(rand.Reader),
		*curves.ED25519(),
		gen,
	)
	assert.NoError(t, err)

	f3, err := crypto.NewFeldman(
		3,
		5,
		3,
		curves.ED25519().NewScalar().Random(rand.Reader),
		*curves.ED25519(),
		gen,
	)
	assert.NoError(t, err)

	f4, err := crypto.NewFeldman(
		3,
		5,
		4,
		curves.ED25519().NewScalar().Random(rand.Reader),
		*curves.ED25519(),
		gen,
	)
	assert.NoError(t, err)

	f5, err := crypto.NewFeldman(
		3,
		5,
		5,
		curves.ED25519().NewScalar().Random(rand.Reader),
		*curves.ED25519(),
		gen,
	)
	assert.NoError(t, err)

	err = f1.SamplePolynomial()
	assert.NoError(t, err)
	err = f2.SamplePolynomial()
	assert.NoError(t, err)
	err = f3.SamplePolynomial()
	assert.NoError(t, err)
	err = f4.SamplePolynomial()
	assert.NoError(t, err)
	err = f5.SamplePolynomial()
	assert.NoError(t, err)
	m1, err := f1.GetPolyFrags()
	assert.NoError(t, err)
	m2, err := f2.GetPolyFrags()
	assert.NoError(t, err)
	m3, err := f3.GetPolyFrags()
	assert.NoError(t, err)
	m4, err := f4.GetPolyFrags()
	assert.NoError(t, err)
	m5, err := f5.GetPolyFrags()
	assert.NoError(t, err)

	_, err = f1.SetPolyFragForParty(2, m2[1])
	assert.NoError(t, err)
	_, err = f1.SetPolyFragForParty(3, m3[1])
	assert.NoError(t, err)
	_, err = f1.SetPolyFragForParty(4, m4[1])
	assert.NoError(t, err)
	z1, err := f1.SetPolyFragForParty(5, m5[1])
	assert.NoError(t, err)

	_, err = f2.SetPolyFragForParty(1, m1[2])
	assert.NoError(t, err)
	_, err = f2.SetPolyFragForParty(3, m3[2])
	assert.NoError(t, err)
	_, err = f2.SetPolyFragForParty(4, m4[2])
	assert.NoError(t, err)
	z2, err := f2.SetPolyFragForParty(5, m5[2])
	assert.NoError(t, err)

	_, err = f3.SetPolyFragForParty(1, m1[3])
	assert.NoError(t, err)
	_, err = f3.SetPolyFragForParty(2, m2[3])
	assert.NoError(t, err)
	_, err = f3.SetPolyFragForParty(4, m4[3])
	assert.NoError(t, err)
	z3, err := f3.SetPolyFragForParty(5, m5[3])
	assert.NoError(t, err)

	_, err = f4.SetPolyFragForParty(1, m1[4])
	assert.NoError(t, err)
	_, err = f4.SetPolyFragForParty(2, m2[4])
	assert.NoError(t, err)
	_, err = f4.SetPolyFragForParty(3, m3[4])
	assert.NoError(t, err)
	z4, err := f4.SetPolyFragForParty(5, m5[4])
	assert.NoError(t, err)

	_, err = f5.SetPolyFragForParty(1, m1[5])
	assert.NoError(t, err)
	_, err = f5.SetPolyFragForParty(2, m2[5])
	assert.NoError(t, err)
	_, err = f5.SetPolyFragForParty(3, m3[5])
	assert.NoError(t, err)
	z5, err := f5.SetPolyFragForParty(4, m4[5])
	assert.NoError(t, err)

	_, err = f1.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	assert.NoError(t, err)
	_, err = f1.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	assert.NoError(t, err)
	_, err = f1.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	assert.NoError(t, err)
	r1, err := f1.ReceiveCommitments(5, z5)
	assert.NoError(t, err)
	assert.NoError(t, err)

	_, err = f2.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f2.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	_, err = f2.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	r2, err := f2.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f3.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f3.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f3.ReceiveCommitments(4, z4)
	assert.NoError(t, err)
	r3, err := f3.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f4.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f4.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f4.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	r4, err := f4.ReceiveCommitments(5, z5)
	assert.NoError(t, err)

	_, err = f5.ReceiveCommitments(1, z1)
	assert.NoError(t, err)
	_, err = f5.ReceiveCommitments(2, z2)
	assert.NoError(t, err)
	_, err = f5.ReceiveCommitments(3, z3)
	assert.NoError(t, err)
	r5, err := f5.ReceiveCommitments(4, z4)
	assert.NoError(t, err)

	_, err = f1.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f1.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f1.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f1.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f2.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f2.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f2.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f2.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f3.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f3.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f3.Recombine(4, r4)
	assert.NoError(t, err)
	_, err = f3.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f4.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f4.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f4.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f4.Recombine(5, r5)
	assert.NoError(t, err)

	_, err = f5.Recombine(1, r1)
	assert.NoError(t, err)
	_, err = f5.Recombine(2, r2)
	assert.NoError(t, err)
	_, err = f5.Recombine(3, r3)
	assert.NoError(t, err)
	_, err = f5.Recombine(4, r4)
	assert.NoError(t, err)
}
