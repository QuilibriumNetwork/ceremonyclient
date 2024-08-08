//
// Copyright Quilibrium, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581/ext"
)

type ScalarBls48581 struct {
	Value *bls48581.BIG
	point Point
}

type PointBls48581G1 struct {
	Value *bls48581.ECP
}

type PointBls48581G2 struct {
	Value *bls48581.ECP8
}

type ScalarBls48581Gt struct {
	Value *bls48581.FP48
}

func (s *ScalarBls48581) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [73]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarBls48581) Hash(bytes []byte) Scalar {
	DST := []byte("BLS_SIG_BLS48581G1_XMD:SHA-512_SVDW_RO_NUL_")
	u := bls48581.Hash_to_field(ext.MC_SHA2, bls48581.HASH_TYPE, DST, bytes, 2)
	u[0].Add(u[1])
	b := u[0].Redc()
	b.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: b,
		point: s.point,
	}
}

func (s *ScalarBls48581) Zero() Scalar {
	return &ScalarBls48581{
		Value: bls48581.NewBIGint(0),
		point: s.point,
	}
}

func (s *ScalarBls48581) One() Scalar {
	return &ScalarBls48581{
		Value: bls48581.NewBIGint(1),
		point: s.point,
	}
}

func (s *ScalarBls48581) IsZero() bool {
	return s.Value.IsZero()
}

func (s *ScalarBls48581) IsOne() bool {
	t := bls48581.NewBIGint(1)
	t.Sub(s.Value)
	return t.IsZero()
}

func (s *ScalarBls48581) IsOdd() bool {
	bytes := make([]byte, bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes[bls48581.MODBYTES-1]&1 == 1
}

func (s *ScalarBls48581) IsEven() bool {
	bytes := make([]byte, bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes[bls48581.MODBYTES-1]&1 == 0
}

func (s *ScalarBls48581) New(value int) Scalar {
	if value > 0 {
		t := bls48581.NewBIGint(value)
		t.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))
		return &ScalarBls48581{
			Value: t,
			point: s.point,
		}
	} else {
		t := bls48581.NewBIGint(-value)
		v := bls48581.NewBIGints(bls48581.CURVE_Order)
		v.Sub(t)
		return &ScalarBls48581{
			Value: v,
			point: s.point,
		}
	}
}

func (s *ScalarBls48581) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		return bls48581.Comp(s.Value, r.Value)
	} else {
		return -2
	}
}

func (s *ScalarBls48581) Square() Scalar {
	sqr := bls48581.NewBIGcopy(s.Value)
	sqr = bls48581.Modsqr(sqr, bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: sqr,
		point: s.point,
	}
}

func (s *ScalarBls48581) Double() Scalar {
	dbl := bls48581.NewBIGcopy(s.Value)
	dbl = bls48581.Modmul(dbl, bls48581.NewBIGint(2), bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: dbl,
		point: s.point,
	}
}

func (s *ScalarBls48581) Invert() (Scalar, error) {
	v := bls48581.NewBIGcopy(s.Value)
	v.Invmodp(bls48581.NewBIGints(bls48581.CURVE_Order))
	if v == nil {
		return nil, fmt.Errorf("inverse doesn't exist")
	}
	return &ScalarBls48581{
		Value: v,
		point: s.point,
	}, nil
}

func (s *ScalarBls48581) Sqrt() (Scalar, error) {
	return nil, errors.New("not supported")
}

func (s *ScalarBls48581) Cube() Scalar {
	value := bls48581.NewBIGcopy(s.Value)
	value = bls48581.Modsqr(value, bls48581.NewBIGints(bls48581.CURVE_Order))
	value = bls48581.Modmul(value, s.Value, bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: value,
		point: s.point,
	}
}

func (s *ScalarBls48581) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		value := bls48581.NewBIGcopy(s.Value)
		value = bls48581.ModAdd(value, r.Value, bls48581.NewBIGints(bls48581.CURVE_Order))
		return &ScalarBls48581{
			Value: value,
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls48581) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		value := bls48581.NewBIGcopy(r.Value)
		value = bls48581.Modneg(value, bls48581.NewBIGints(bls48581.CURVE_Order))
		value = bls48581.ModAdd(value, s.Value, bls48581.NewBIGints(bls48581.CURVE_Order))
		return &ScalarBls48581{
			Value: value,
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls48581) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		value := bls48581.NewBIGcopy(s.Value)
		value = bls48581.Modmul(value, r.Value, bls48581.NewBIGints(bls48581.CURVE_Order))
		return &ScalarBls48581{
			Value: value,
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls48581) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarBls48581) Div(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		value := bls48581.NewBIGcopy(r.Value)
		value.Invmodp(bls48581.NewBIGints(bls48581.CURVE_Order))
		value = bls48581.Modmul(value, s.Value, bls48581.NewBIGints(bls48581.CURVE_Order))
		return &ScalarBls48581{
			Value: value,
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls48581) Neg() Scalar {
	value := bls48581.NewBIGcopy(s.Value)
	value = bls48581.Modneg(value, bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: value,
		point: s.point,
	}
}

func (s *ScalarBls48581) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := make([]byte, bls48581.MODBYTES)
	b := v.Bytes()
	copy(t[bls48581.MODBYTES-uint(len(b)):], b)

	i := bls48581.FromBytes(t)
	i.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))
	return &ScalarBls48581{
		Value: i,
		point: s.point,
	}, nil
}

func (s *ScalarBls48581) BigInt() *big.Int {
	bytes := make([]byte, bls48581.MODBYTES)
	s.Value.ToBytes(bytes)

	return new(big.Int).SetBytes(bytes)
}

func (s *ScalarBls48581) Bytes() []byte {
	t := make([]byte, bls48581.MODBYTES)
	s.Value.ToBytes(t)

	return t
}

func (s *ScalarBls48581) SetBytes(bytes []byte) (Scalar, error) {
	var seq [bls48581.MODBYTES]byte
	copy(seq[bls48581.MODBYTES-uint(len(bytes)):], bytes)
	value := bls48581.FromBytes(seq[:])

	if value == nil {
		return nil, errors.New("could not deserialize")
	}
	return &ScalarBls48581{
		value, s.point,
	}, nil
}

func (s *ScalarBls48581) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) != int(bls48581.MODBYTES) {
		return nil, fmt.Errorf("invalid length")
	}
	var seq [bls48581.MODBYTES]byte
	copy(seq[:], bytes)
	value := bls48581.FromBytes(seq[:])
	if value == nil {
		return nil, errors.New("could not deserialize")
	}
	return &ScalarBls48581{
		value, s.point,
	}, nil
}

func (s *ScalarBls48581) Point() Point {
	return s.point.Identity()
}

func (s *ScalarBls48581) Clone() Scalar {
	value := bls48581.NewBIGcopy(s.Value)
	return &ScalarBls48581{
		Value: value,
		point: s.point,
	}
}

func (s *ScalarBls48581) SetPoint(p Point) PairingScalar {
	value := bls48581.NewBIGcopy(s.Value)
	return &ScalarBls48581{
		Value: value,
		point: p,
	}
}

func (s *ScalarBls48581) Order() *big.Int {
	b := bls48581.NewBIGints(bls48581.CURVE_Order)
	bytes := make([]byte, bls48581.MODBYTES)
	b.ToBytes(bytes)
	return new(big.Int).SetBytes(bytes)
}

func (s *ScalarBls48581) MarshalBinary() ([]byte, error) {
	bytes := make([]byte, bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes, nil
}

func (s *ScalarBls48581) UnmarshalBinary(input []byte) error {
	sc, err := new(ScalarBls48581).SetBytes(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls48581)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	s.point = ss.point
	return nil
}

func (s *ScalarBls48581) MarshalText() ([]byte, error) {
	return []byte(s.Value.ToString()), nil
}

func (s *ScalarBls48581) UnmarshalText(input []byte) error {
	return errors.New("unsupported")
}

func (s *ScalarBls48581) MarshalJSON() ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (s *ScalarBls48581) UnmarshalJSON(input []byte) error {
	return errors.New("unsupported")
}

func (p *PointBls48581G1) Random(reader io.Reader) Point {
	var seed [73]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointBls48581G1) Hash(bytes []byte) Point {
	pt := bls48581.Bls256_hash_to_point(bytes)
	return &PointBls48581G1{Value: pt}
}

func (p *PointBls48581G1) Identity() Point {
	g1 := bls48581.ECP_generator()
	g1 = g1.Mul(bls48581.NewBIGint(0))
	return &PointBls48581G1{
		Value: g1,
	}
}

func (p *PointBls48581G1) Generator() Point {
	g1 := bls48581.ECP_generator()

	return &PointBls48581G1{
		Value: g1,
	}
}

func (p *PointBls48581G1) IsIdentity() bool {
	return p.Value.Is_infinity()
}

func (p *PointBls48581G1) IsNegative() bool {
	// This bit represents the sign of the `y` coordinate which is what we want
	bytes := make([]byte, bls48581.MODBYTES+1)
	p.Value.ToBytes(bytes, true)
	return bytes[0] == 0x03
}

func (p *PointBls48581G1) IsOnCurve() bool {
	return bls48581.G1member(p.Value)
}

func (p *PointBls48581G1) Double() Point {
	v := bls48581.NewECP()
	v.Copy(p.Value)
	v.Dbl()
	return &PointBls48581G1{v}
}

func (p *PointBls48581G1) Scalar() Scalar {
	value := bls48581.NewBIG()
	return &ScalarBls48581{
		Value: value,
		point: new(PointBls48581G1),
	}
}

func (p *PointBls48581G1) Neg() Point {
	v := bls48581.NewECP()
	v.Copy(p.Value)
	v.Neg()
	return &PointBls48581G1{v}
}

func (p *PointBls48581G1) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls48581G1)
	if ok {
		v := bls48581.NewECP()
		v.Copy(p.Value)
		v.Add(r.Value)
		return &PointBls48581G1{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G1) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls48581G1)
	if ok {
		v := bls48581.NewECP()
		v.Copy(p.Value)
		v.Sub(r.Value)
		return &PointBls48581G1{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G1) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		v := bls48581.NewECP()
		v.Copy(p.Value)
		v = v.Mul(r.Value)
		return &PointBls48581G1{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G1) Equal(rhs Point) bool {
	r, ok := rhs.(*PointBls48581G1)
	if ok {
		return p.Value.Equals(r.Value)
	} else {
		return false
	}
}

func (p *PointBls48581G1) Set(x, y *big.Int) (Point, error) {
	xBytes := make([]byte, bls48581.MODBYTES)
	yBytes := make([]byte, bls48581.MODBYTES)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	xBig := bls48581.FromBytes(xBytes)
	yBig := bls48581.FromBytes(yBytes)
	v := bls48581.NewECPbigs(xBig, yBig)
	if v == nil {
		return nil, fmt.Errorf("invalid coordinates")
	}
	return &PointBls48581G1{v}, nil
}

func (p *PointBls48581G1) ToAffineCompressed() []byte {
	out := make([]byte, bls48581.MODBYTES+1)
	p.Value.ToBytes(out, true)
	return out[:]
}

func (p *PointBls48581G1) ToAffineUncompressed() []byte {
	out := make([]byte, bls48581.MODBYTES*2+1)
	p.Value.ToBytes(out, false)
	return out[:]
}

func (p *PointBls48581G1) FromAffineCompressed(bytes []byte) (Point, error) {
	var b [bls48581.MODBYTES + 1]byte
	copy(b[:], bytes)
	value := bls48581.ECP_fromBytes(b[:])
	if value == nil || value.Is_infinity() {
		return nil, errors.New("could not decode")
	}
	return &PointBls48581G1{value}, nil
}

func (p *PointBls48581G1) FromAffineUncompressed(bytes []byte) (Point, error) {
	var b [bls48581.MODBYTES*2 + 1]byte
	copy(b[:], bytes)
	value := bls48581.ECP_fromBytes(b[:])
	if value == nil || value.Is_infinity() {
		return nil, errors.New("could not decode")
	}
	return &PointBls48581G1{value}, nil
}

func (p *PointBls48581G1) CurveName() string {
	return "bls48581G1"
}

func (p *PointBls48581G1) SumOfProducts(points []Point, scalars []Scalar) Point {
	nPoints := make([]*bls48581.ECP, len(points))
	nScalars := make([]*bls48581.BIG, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointBls48581G1)
		if !ok {
			return nil
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarBls48581)
		if !ok {
			return nil
		}
		nScalars[i] = s.Value
	}
	value := bls48581.ECP_muln(len(points), nPoints, nScalars)
	if value == nil || value.Is_infinity() {
		return nil
	}
	return &PointBls48581G1{value}
}

func (p *PointBls48581G1) OtherGroup() PairingPoint {
	return new(PointBls48581G2).Identity().(PairingPoint)
}

func (p *PointBls48581G1) Pairing(rhs PairingPoint) Scalar {
	pt, ok := rhs.(*PointBls48581G2)
	if !ok {
		return nil
	}

	pair := bls48581.Ate(pt.Value, p.Value)

	return &ScalarBls48581Gt{pair}
}

func (p *PointBls48581G1) Ate2Pairing(
	rhs *PointBls48581G2,
	lhs2 *PointBls48581G1,
	rhs2 *PointBls48581G2,
) Scalar {
	ate2 := bls48581.Ate2(rhs2.Value, p.Value, rhs2.Value, lhs2.Value)

	return &ScalarBls48581Gt{ate2}
}

func (p *PointBls48581G1) MultiPairing(points ...PairingPoint) Scalar {
	return bls48multiPairing(points...)
}

func (p *PointBls48581G1) X() *big.Int {
	bytes := make([]byte, bls48581.MODBYTES)
	p.Value.GetX().ToBytes(bytes[:])
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G1) Y() *big.Int {
	bytes := make([]byte, bls48581.MODBYTES)
	p.Value.GetY().ToBytes(bytes[:])
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G1) Modulus() *big.Int {
	b := bls48581.NewBIGints(bls48581.Modulus)
	bytes := make([]byte, bls48581.MODBYTES)
	b.ToBytes(bytes)
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G1) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointBls48581G1) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls48581G1)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls48581G1) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointBls48581G1) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls48581G1)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls48581G1) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointBls48581G1) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointBls48581G1)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.Value = P.Value
	return nil
}

func (p *PointBls48581G2) Random(reader io.Reader) Point {
	var seed [73]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointBls48581G2) Hash(bytes []byte) Point {
	DST := []byte("BLS_SIG_BLS48581G2_XMD:SHA-512_SVDW_RO_NUL_")
	u := bls48581.Hash_to_field(ext.MC_SHA2, bls48581.HASH_TYPE, DST, bytes, 2)
	u[0].Add(u[1])
	fp8 := bls48581.NewFP8fp(u[0])
	v := bls48581.ECP8_map2point(fp8)
	return &PointBls48581G2{v}
}

func (p *PointBls48581G2) Identity() Point {
	g2 := bls48581.ECP8_generator()
	g2 = g2.Mul(bls48581.NewBIGint(0))
	return &PointBls48581G2{
		Value: g2,
	}
}

func (p *PointBls48581G2) Generator() Point {
	g2 := bls48581.ECP8_generator()

	return &PointBls48581G2{
		Value: g2,
	}
}

func (p *PointBls48581G2) IsIdentity() bool {
	return p.Value.Is_infinity()
}

func (p *PointBls48581G2) IsNegative() bool {
	// This bit represents the sign of the `y` coordinate which is what we want
	bytes := make([]byte, bls48581.MODBYTES+1)
	p.Value.ToBytes(bytes, true)
	return bytes[0] == 0x03
}

func (p *PointBls48581G2) IsOnCurve() bool {
	return bls48581.G2member(p.Value)
}

func (p *PointBls48581G2) Double() Point {
	v := bls48581.NewECP8()
	v.Copy(p.Value)
	v.Dbl()
	return &PointBls48581G2{v}
}

func (p *PointBls48581G2) Scalar() Scalar {
	value := bls48581.NewBIG()
	return &ScalarBls48581{
		Value: value,
		point: new(PointBls48581G2),
	}
}

func (p *PointBls48581G2) Neg() Point {
	v := bls48581.NewECP8()
	v.Copy(p.Value)
	v.Neg()
	return &PointBls48581G2{v}
}

func (p *PointBls48581G2) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls48581G2)
	if ok {
		v := bls48581.NewECP8()
		v.Copy(p.Value)
		v.Add(r.Value)
		return &PointBls48581G2{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G2) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls48581G2)
	if ok {
		v := bls48581.NewECP8()
		v.Copy(p.Value)
		v.Sub(r.Value)
		return &PointBls48581G2{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G2) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarBls48581)
	if ok {
		v := bls48581.NewECP8()
		v.Copy(p.Value)
		bytes := make([]byte, bls48581.MODBYTES)
		r.Value.ToBytes(bytes)
		v = v.Mul(bls48581.FromBytes(bytes))
		return &PointBls48581G2{v}
	} else {
		return nil
	}
}

func (p *PointBls48581G2) Equal(rhs Point) bool {
	r, ok := rhs.(*PointBls48581G2)
	if ok {
		return p.Value.Equals(r.Value)
	} else {
		return false
	}
}

func (p *PointBls48581G2) Set(x, y *big.Int) (Point, error) {
	xBytes := make([]byte, 4*bls48581.MODBYTES)
	yBytes := make([]byte, 4*bls48581.MODBYTES)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	xBig := bls48581.FP8_fromBytes(xBytes)
	yBig := bls48581.FP8_fromBytes(yBytes)
	v := bls48581.NewECP8fp8s(xBig, yBig)
	if v == nil || v.Is_infinity() {
		return nil, fmt.Errorf("invalid coordinates")
	}
	return &PointBls48581G2{v}, nil
}

func (p *PointBls48581G2) ToAffineCompressed() []byte {
	out := make([]byte, bls48581.MODBYTES*8+1)
	p.Value.ToBytes(out, true)
	return out[:]
}

func (p *PointBls48581G2) ToAffineUncompressed() []byte {
	out := make([]byte, bls48581.MODBYTES*16+1)
	p.Value.ToBytes(out, false)
	return out[:]
}

func (p *PointBls48581G2) FromAffineCompressed(bytes []byte) (Point, error) {
	var b [bls48581.MODBYTES*8 + 1]byte
	copy(b[:], bytes)
	value := bls48581.ECP8_fromBytes(b[:])
	if value == nil || value.Is_infinity() {
		return nil, errors.New("could not decode")
	}
	return &PointBls48581G2{value}, nil
}

func (p *PointBls48581G2) FromAffineUncompressed(bytes []byte) (Point, error) {
	var b [bls48581.MODBYTES*16 + 1]byte
	copy(b[:], bytes)
	value := bls48581.ECP8_fromBytes(b[:])
	if value == nil || value.Is_infinity() {
		return nil, errors.New("could not decode")
	}
	return &PointBls48581G2{value}, nil
}

func (p *PointBls48581G2) CurveName() string {
	return "bls48581G2"
}

func (p *PointBls48581G2) SumOfProducts(points []Point, scalars []Scalar) Point {
	nPoints := make([]*bls48581.ECP8, len(points))
	nScalars := make([]*bls48581.BIG, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointBls48581G2)
		if !ok {
			return nil
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarBls48581)
		if !ok {
			return nil
		}
		nScalars[i] = s.Value
	}
	value := bls48581.Mul16(nPoints, nScalars)
	if value == nil || value.Is_infinity() {
		return nil
	}
	return &PointBls48581G2{value}
}

func (p *PointBls48581G2) OtherGroup() PairingPoint {
	return new(PointBls48581G2).Identity().(PairingPoint)
}

func (p *PointBls48581G2) Pairing(rhs PairingPoint) Scalar {
	pt, ok := rhs.(*PointBls48581G1)
	if !ok {
		return nil
	}

	value := bls48581.Ate(p.Value, pt.Value)

	return &ScalarBls48581Gt{value}
}

func (p *PointBls48581G2) MultiPairing(points ...PairingPoint) Scalar {
	return bls48multiPairing(points...)
}

func (p *PointBls48581G2) X() *big.Int {
	x := p.Value.GetX()
	bytes := make([]byte, 8*bls48581.MODBYTES)
	x.ToBytes(bytes)
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G2) Y() *big.Int {
	y := p.Value.GetY()
	bytes := make([]byte, 8*bls48581.MODBYTES)
	y.ToBytes(bytes)
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G2) Modulus() *big.Int {
	b := bls48581.NewBIGints(bls48581.Modulus)
	bytes := make([]byte, bls48581.MODBYTES)
	b.ToBytes(bytes)
	return new(big.Int).SetBytes(bytes)
}

func (p *PointBls48581G2) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointBls48581G2) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls48581G2)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls48581G2) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointBls48581G2) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls48581G2)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls48581G2) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointBls48581G2) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointBls48581G2)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.Value = P.Value
	return nil
}

func bls48multiPairing(points ...PairingPoint) Scalar {
	if len(points)%2 != 0 {
		return nil
	}
	valid := true
	r := bls48581.Initmp()
	for i := 0; i < len(points); i += 2 {
		pt1, ok := points[i].(*PointBls48581G1)
		valid = valid && ok
		pt2, ok := points[i+1].(*PointBls48581G2)
		valid = valid && ok
		if valid {
			bls48581.Another(r, pt2.Value, pt1.Value)
		}
	}
	if !valid {
		return nil
	}

	v := bls48581.Miller(r)
	v = bls48581.Fexp(v)
	return &ScalarBls48581Gt{v}
}

func (s *ScalarBls48581Gt) Random(reader io.Reader) Scalar {
	bytes := make([]byte, 48*bls48581.MODBYTES)
	reader.Read(bytes)
	value := bls48581.FP48_fromBytes(bytes)
	if value == nil {
		return nil
	}
	return &ScalarBls48581Gt{value}
}

func (s *ScalarBls48581Gt) Hash(bytes []byte) Scalar {
	reader := sha3.NewShake256()
	n, err := reader.Write(bytes)
	if err != nil {
		return nil
	}
	if n != len(bytes) {
		return nil
	}
	return s.Random(reader)
}

func (s *ScalarBls48581Gt) Zero() Scalar {
	return &ScalarBls48581Gt{bls48581.NewFP48int(0)}
}

func (s *ScalarBls48581Gt) One() Scalar {
	return &ScalarBls48581Gt{bls48581.NewFP48int(1)}
}

func (s *ScalarBls48581Gt) IsZero() bool {
	return s.Value.IsZero()
}

func (s *ScalarBls48581Gt) IsOne() bool {
	return s.Value.Isunity()
}

func (s *ScalarBls48581Gt) MarshalBinary() ([]byte, error) {
	return s.Bytes(), nil
}

func (s *ScalarBls48581Gt) UnmarshalBinary(input []byte) error {
	sc, err := new(ScalarBls48581Gt).SetBytes(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls48581Gt)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarBls48581Gt) MarshalText() ([]byte, error) {
	return []byte(s.Value.ToString()), nil
}

func (s *ScalarBls48581Gt) UnmarshalText(input []byte) error {
	return errors.New("unsupported")
}

func (s *ScalarBls48581Gt) MarshalJSON() ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (s *ScalarBls48581Gt) UnmarshalJSON(input []byte) error {
	return errors.New("unsupported")
}

func (s *ScalarBls48581Gt) IsOdd() bool {
	bytes := make([]byte, 48*bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes[0]&1 == 1
}

func (s *ScalarBls48581Gt) IsEven() bool {
	bytes := make([]byte, 48*bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes[0]&1 == 0
}

func (s *ScalarBls48581Gt) New(input int) Scalar {
	fp := bls48581.NewFP48int(input)
	return &ScalarBls48581Gt{fp}
}

func (s *ScalarBls48581Gt) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarBls48581Gt)
	if ok && s.Value.Equals(r.Value) {
		return 0
	} else {
		return -2
	}
}

func (s *ScalarBls48581Gt) Square() Scalar {
	v := bls48581.NewFP48copy(s.Value)
	v.Sqr()
	return &ScalarBls48581Gt{v}
}

func (s *ScalarBls48581Gt) Double() Scalar {
	v := bls48581.NewFP48copy(s.Value)
	v.Mul(bls48581.NewFP48int(2))
	return &ScalarBls48581Gt{v}
}

func (s *ScalarBls48581Gt) Invert() (Scalar, error) {
	v := bls48581.NewFP48copy(s.Value)
	v.Invert()
	if v == nil {
		return nil, fmt.Errorf("not invertible")
	}
	return &ScalarBls48581Gt{v}, nil
}

func (s *ScalarBls48581Gt) Sqrt() (Scalar, error) {
	// Not implemented
	return nil, nil
}

func (s *ScalarBls48581Gt) Cube() Scalar {
	v := bls48581.NewFP48copy(s.Value)
	v.Sqr()
	v.Mul(s.Value)
	return &ScalarBls48581Gt{v}
}

func (s *ScalarBls48581Gt) Add(rhs Scalar) Scalar {
	// not supported
	return nil
}

func (s *ScalarBls48581Gt) Sub(rhs Scalar) Scalar {
	// not supported
	return nil
}

func (s *ScalarBls48581Gt) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581Gt)
	if ok {
		v := bls48581.NewFP48copy(s.Value)
		v.Mul(r.Value)
		return &ScalarBls48581Gt{v}
	} else {
		return nil
	}
}

func (s *ScalarBls48581Gt) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarBls48581Gt) Div(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls48581Gt)
	if ok {
		v := bls48581.NewFP48copy(r.Value)
		v.Invert()
		v.Mul(s.Value)
		return &ScalarBls48581Gt{v}
	} else {
		return nil
	}
}

func (s *ScalarBls48581Gt) Neg() Scalar {
	return nil
}

func (s *ScalarBls48581Gt) SetBigInt(v *big.Int) (Scalar, error) {
	return nil, errors.New("unsupported")
}

func (s *ScalarBls48581Gt) BigInt() *big.Int {
	return nil
}

func (s *ScalarBls48581Gt) Point() Point {
	return (&PointBls48581G1{}).Identity()
}

func (s *ScalarBls48581Gt) Bytes() []byte {
	bytes := make([]byte, 48*bls48581.MODBYTES)
	s.Value.ToBytes(bytes)
	return bytes[:]
}

func (s *ScalarBls48581Gt) SetBytes(bytes []byte) (Scalar, error) {
	b := make([]byte, 48*bls48581.MODBYTES)
	copy(b[:], bytes)
	ss := bls48581.FP48_fromBytes(b)
	if ss == nil {
		return nil, fmt.Errorf("invalid bytes")
	}
	return &ScalarBls48581Gt{ss}, nil
}

func (s *ScalarBls48581Gt) SetBytesWide(bytes []byte) (Scalar, error) {
	b := make([]byte, 48*bls48581.MODBYTES)
	copy(b[:], bytes)
	ss := bls48581.FP48_fromBytes(b)
	if ss == nil {
		return nil, fmt.Errorf("invalid bytes")
	}
	return &ScalarBls48581Gt{ss}, nil
}

func (s *ScalarBls48581Gt) Clone() Scalar {
	fp := bls48581.NewFP48copy(s.Value)
	return &ScalarBls48581Gt{
		Value: fp,
	}
}
