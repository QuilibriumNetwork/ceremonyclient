/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* MiotCL Weierstrass elliptic curve functions over FP2 */

package bls48581

import (
	"arena"
)

type ECP8 struct {
	x *FP8
	y *FP8
	z *FP8
}

func NewECP8(mem *arena.Arena) *ECP8 {
	var E *ECP8
	if mem != nil {
		E = arena.New[ECP8](mem)
		E.x = NewFP8(mem)
		E.y = NewFP8int(1, mem)
		E.z = NewFP8(mem)
	} else {
		E = new(ECP8)
		E.x = NewFP8(nil)
		E.y = NewFP8int(1, nil)
		E.z = NewFP8(nil)
	}

	return E
}

/* Test this=O? */
func (E *ECP8) Is_infinity(mem *arena.Arena) bool {
	return E.x.IsZero(mem) && E.z.IsZero(mem)
}

/* copy this=P */
func (E *ECP8) Copy(P *ECP8) {
	E.x.copy(P.x)
	E.y.copy(P.y)
	E.z.copy(P.z)
}

/* set this=O */
func (E *ECP8) inf() {
	E.x.zero()
	E.y.one()
	E.z.zero()
}

/* set this=-this */
func (E *ECP8) Neg(mem *arena.Arena) {
	E.y.norm()
	E.y.Neg(mem)
	E.y.norm()
}

/* Conditional move of Q to P dependant on d */
func (E *ECP8) cmove(Q *ECP8, d int) {
	E.x.cmove(Q.x, d)
	E.y.cmove(Q.y, d)
	E.z.cmove(Q.z, d)
}

/* Constant time select from pre-computed table */
func (E *ECP8) selector(W []*ECP8, b int32) {
	MP := NewECP8(nil)
	m := b >> 31
	babs := (b ^ m) - m

	babs = (babs - 1) / 2

	E.cmove(W[0], teq(babs, 0)) // conditional move
	E.cmove(W[1], teq(babs, 1))
	E.cmove(W[2], teq(babs, 2))
	E.cmove(W[3], teq(babs, 3))
	E.cmove(W[4], teq(babs, 4))
	E.cmove(W[5], teq(babs, 5))
	E.cmove(W[6], teq(babs, 6))
	E.cmove(W[7], teq(babs, 7))

	MP.Copy(E)
	MP.Neg(nil)
	E.cmove(MP, int(m&1))
}

/* Test if P == Q */
func (E *ECP8) Equals(Q *ECP8) bool {
	mem := arena.NewArena()
	defer mem.Free()
	a := NewFP8copy(E.x, mem)
	b := NewFP8copy(Q.x, mem)
	a.Mul(Q.z, mem)
	b.Mul(E.z, mem)

	if !a.Equals(b) {
		return false
	}
	a.copy(E.y)
	b.copy(Q.y)
	a.Mul(Q.z, mem)
	b.Mul(E.z, mem)
	if !a.Equals(b) {
		return false
	}

	return true
}

/* set to Affine - (x,y,z) to (x,y) */
func (E *ECP8) Affine(mem *arena.Arena) {
	if E.Is_infinity(mem) {
		return
	}
	one := NewFP8int(1, mem)
	if E.z.Equals(one) {
		E.x.reduce(mem)
		E.y.reduce(mem)
		return
	}
	E.z.Invert(nil, mem)

	E.x.Mul(E.z, mem)
	E.x.reduce(mem)
	E.y.Mul(E.z, mem)
	E.y.reduce(mem)
	E.z.copy(one)
}

/* extract affine x as FP2 */
func (E *ECP8) GetX(mem *arena.Arena) *FP8 {
	W := NewECP8(mem)
	W.Copy(E)
	W.Affine(mem)
	return W.x
}

/* extract affine y as FP2 */
func (E *ECP8) GetY(mem *arena.Arena) *FP8 {
	W := NewECP8(mem)
	W.Copy(E)
	W.Affine(mem)
	return W.y
}

/* extract projective x */
func (E *ECP8) getx() *FP8 {
	return E.x
}

/* extract projective y */
func (E *ECP8) gety() *FP8 {
	return E.y
}

/* extract projective z */
func (E *ECP8) getz() *FP8 {
	return E.z
}

/* convert to byte array */
func (E *ECP8) ToBytes(b []byte, compress bool) {
	var t [8 * int(MODBYTES)]byte
	MB := 8 * int(MODBYTES)
	W := NewECP8(nil)
	W.Copy(E)
	W.Affine(nil)
	W.x.ToBytes(t[:])

	for i := 0; i < MB; i++ {
		b[i+1] = t[i]
	}
	if !compress {
		b[0] = 0x04
		W.y.ToBytes(t[:])
		for i := 0; i < MB; i++ {
			b[i+MB+1] = t[i]
		}
	} else {
		b[0] = 0x02
		if W.y.sign(nil) == 1 {
			b[0] = 0x03
		}
	}
}

/* convert from byte array to point */
func ECP8_fromBytes(b []byte) *ECP8 {
	var t [8 * int(MODBYTES)]byte
	MB := 8 * int(MODBYTES)
	typ := int(b[0])

	for i := 0; i < MB; i++ {
		t[i] = b[i+1]
	}
	rx := FP8_fromBytes(t[:])
	if typ == 0x04 {
		for i := 0; i < MB; i++ {
			t[i] = b[i+MB+1]
		}
		ry := FP8_fromBytes(t[:])
		return NewECP8fp8s(rx, ry, nil)
	} else {
		return NewECP8fp8(rx, typ&1, nil)
	}
}

/* convert this to hex string */
func (E *ECP8) ToString() string {
	W := NewECP8(nil)
	W.Copy(E)
	W.Affine(nil)
	if W.Is_infinity(nil) {
		return "infinity"
	}
	return "(" + W.x.toString() + "," + W.y.toString() + ")"
}

/* Calculate RHS of twisted curve equation x^3+B/i */
func RHS8(x *FP8, mem *arena.Arena) *FP8 {
	r := NewFP8copy(x, mem)
	r.Sqr(mem)
	b2 := NewFP2big(NewBIGints(CURVE_B, mem), mem)
	b4 := NewFP4fp2(b2, mem)
	b := NewFP8fp4(b4, mem)

	b.div_i(mem)
	r.Mul(x, mem)
	r.Add(b, mem)

	r.reduce(mem)
	return r
}

/* construct this from (x,y) - but set to O if not on curve */
func NewECP8fp8s(ix *FP8, iy *FP8, mem *arena.Arena) *ECP8 {
	var E *ECP8
	if mem != nil {
		E = arena.New[ECP8](mem)
	} else {
		E = new(ECP8)
	}
	E.x = NewFP8copy(ix, mem)
	E.y = NewFP8copy(iy, mem)
	E.z = NewFP8int(1, mem)
	E.x.norm()
	rhs := RHS8(E.x, mem)
	y2 := NewFP8copy(E.y, mem)
	y2.Sqr(mem)
	if !y2.Equals(rhs) {
		E.inf()
	}
	return E
}

/* construct this from x - but set to O if not on curve */
func NewECP8fp8(ix *FP8, s int, mem *arena.Arena) *ECP8 {
	var E *ECP8
	if mem != nil {
		E = arena.New[ECP8](mem)
	} else {
		E = new(ECP8)
	}
	h := NewFP(mem)
	E.x = NewFP8copy(ix, mem)
	E.y = NewFP8int(1, mem)
	E.z = NewFP8int(1, mem)
	E.x.norm()
	rhs := RHS8(E.x, mem)
	if rhs.qr(h) == 1 {
		rhs.Sqrt(h, mem)
		if rhs.sign(mem) != s {
			rhs.Neg(mem)
		}
		rhs.reduce(mem)
		E.y.copy(rhs)

	} else {
		E.inf()
	}
	return E
}

/* this+=this */
func (E *ECP8) Dbl(mem *arena.Arena) int {
	iy := NewFP8copy(E.y, mem)
	iy.times_i(mem)

	t0 := NewFP8copy(E.y, mem)
	t0.Sqr(mem)
	t0.times_i(mem)
	t1 := NewFP8copy(iy, mem)
	t1.Mul(E.z, mem)
	t2 := NewFP8copy(E.z, mem)
	t2.Sqr(mem)

	E.z.copy(t0)
	E.z.Add(t0, mem)
	E.z.norm()
	E.z.Add(E.z, mem)
	E.z.Add(E.z, mem)
	E.z.norm()

	t2.imul(3*CURVE_B_I, mem)
	x3 := NewFP8copy(t2, mem)
	x3.Mul(E.z, mem)

	y3 := NewFP8copy(t0, mem)

	y3.Add(t2, mem)
	y3.norm()
	E.z.Mul(t1, mem)
	t1.copy(t2)
	t1.Add(t2, mem)
	t2.Add(t1, mem)
	t2.norm()
	t0.Sub(t2, mem)
	t0.norm() //y^2-9bz^2
	y3.Mul(t0, mem)
	y3.Add(x3, mem) //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
	t1.copy(E.x)
	t1.Mul(iy, mem) //
	E.x.copy(t0)
	E.x.norm()
	E.x.Mul(t1, mem)
	E.x.Add(E.x, mem) //(y^2-9bz^2)xy2

	E.x.norm()
	E.y.copy(y3)
	E.y.norm()

	return 1
}

/* this+=Q - return 0 for Add, 1 for double, -1 for O */
func (E *ECP8) Add(Q *ECP8, mem *arena.Arena) int {
	b := 3 * CURVE_B_I
	t0 := NewFP8copy(E.x, mem)
	t0.Mul(Q.x, mem) // x.Q.x
	t1 := NewFP8copy(E.y, mem)
	t1.Mul(Q.y, mem) // y.Q.y

	t2 := NewFP8copy(E.z, mem)
	t2.Mul(Q.z, mem)
	t3 := NewFP8copy(E.x, mem)
	t3.Add(E.y, mem)
	t3.norm() //t3=X1+Y1
	t4 := NewFP8copy(Q.x, mem)
	t4.Add(Q.y, mem)
	t4.norm()       //t4=X2+Y2
	t3.Mul(t4, mem) //t3=(X1+Y1)(X2+Y2)
	t4.copy(t0)
	t4.Add(t1, mem) //t4=X1.X2+Y1.Y2

	t3.Sub(t4, mem)
	t3.norm()
	t3.times_i(mem) //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
	t4.copy(E.y)
	t4.Add(E.z, mem)
	t4.norm() //t4=Y1+Z1
	x3 := NewFP8copy(Q.y, mem)
	x3.Add(Q.z, mem)
	x3.norm() //x3=Y2+Z2

	t4.Mul(x3, mem) //t4=(Y1+Z1)(Y2+Z2)
	x3.copy(t1)     //
	x3.Add(t2, mem) //X3=Y1.Y2+Z1.Z2

	t4.Sub(x3, mem)
	t4.norm()
	t4.times_i(mem) //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
	x3.copy(E.x)
	x3.Add(E.z, mem)
	x3.norm() // x3=X1+Z1
	y3 := NewFP8copy(Q.x, mem)
	y3.Add(Q.z, mem)
	y3.norm()       // y3=X2+Z2
	x3.Mul(y3, mem) // x3=(X1+Z1)(X2+Z2)
	y3.copy(t0)
	y3.Add(t2, mem) // y3=X1.X2+Z1+Z2
	y3.rsub(x3, mem)
	y3.norm() // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

	t0.times_i(mem) // x.Q.x
	t1.times_i(mem) // y.Q.y
	x3.copy(t0)
	x3.Add(t0, mem)
	t0.Add(x3, mem)
	t0.norm()
	t2.imul(b, mem)
	z3 := NewFP8copy(t1, mem)
	z3.Add(t2, mem)
	z3.norm()
	t1.Sub(t2, mem)
	t1.norm()
	y3.imul(b, mem)
	x3.copy(y3)
	x3.Mul(t4, mem)
	t2.copy(t3)
	t2.Mul(t1, mem)
	x3.rsub(t2, mem)
	y3.Mul(t0, mem)
	t1.Mul(z3, mem)
	y3.Add(t1, mem)
	t0.Mul(t3, mem)
	z3.Mul(t4, mem)
	z3.Add(t0, mem)

	E.x.copy(x3)
	E.x.norm()
	E.y.copy(y3)
	E.y.norm()
	E.z.copy(z3)
	E.z.norm()

	return 0
}

/* set this-=Q */
func (E *ECP8) Sub(Q *ECP8, mem *arena.Arena) int {
	NQ := NewECP8(mem)
	NQ.Copy(Q)
	NQ.Neg(mem)
	D := E.Add(NQ, mem)
	return D
}

func ECP8_frob_constants() [3]*FP2 {
	Fra := NewBIGints(Fra, nil)
	Frb := NewBIGints(Frb, nil)
	X := NewFP2bigs(Fra, Frb, nil)

	F0 := NewFP2copy(X, nil)
	F0.Sqr(nil)
	F2 := NewFP2copy(F0, nil)
	F2.Mul_ip(nil)
	F2.norm()
	F1 := NewFP2copy(F2, nil)
	F1.Sqr(nil)
	F2.Mul(F1, nil)

	F2.Mul_ip(nil)
	F2.norm()

	F1.copy(X)

	F0.copy(F1)
	F0.Sqr(nil)
	F1.Mul(F0, nil)
	F0.Mul_ip(nil)
	F0.norm()
	F1.Mul_ip(nil)
	F1.norm()
	F1.Mul_ip(nil)
	F1.norm()

	F := [3]*FP2{F0, F1, F2}
	return F
}

/* set this*=q, where q is Modulus, using Frobenius */
func (E *ECP8) frob(F [3]*FP2, n int) {
	for i := 0; i < n; i++ {
		E.x.frob(F[2], nil)
		E.x.qmul(F[0], nil)
		E.x.times_i2(nil)
		E.y.frob(F[2], nil)
		E.y.qmul(F[1], nil)
		E.y.times_i(nil)
		E.z.frob(F[2], nil)
	}
}

/* P*=e */
func (E *ECP8) mul(e *BIG, mem *arena.Arena) *ECP8 {
	/* fixed size windows */
	mt := NewBIG(mem)
	t := NewBIG(mem)
	P := NewECP8(nil)
	Q := NewECP8(mem)
	C := NewECP8(mem)

	if E.Is_infinity(mem) {
		return NewECP8(mem)
	}

	var W []*ECP8
	var w [1 + (NLEN*int(BASEBITS)+3)/4]int8

	/* precompute table */
	Q.Copy(E)
	Q.Dbl(mem)

	W = append(W, NewECP8(mem))
	W[0].Copy(E)

	for i := 1; i < 8; i++ {
		W = append(W, NewECP8(mem))
		W[i].Copy(W[i-1])
		W[i].Add(Q, mem)
	}

	/* make exponent odd - Add 2P if even, P if odd */
	t.copy(e)
	s := int(t.parity())
	t.inc(1)
	t.norm()
	ns := int(t.parity())
	mt.copy(t)
	mt.inc(1)
	mt.norm()
	t.cmove(mt, s)
	Q.cmove(E, ns)
	C.Copy(Q)

	nb := 1 + (t.nbits()+3)/4
	/* convert exponent to signed 4-bit window */
	for i := 0; i < nb; i++ {
		w[i] = int8(t.lastbits(5) - 16)
		t.dec(int(w[i]))
		t.norm()
		t.fshr(4)
	}
	w[nb] = int8(t.lastbits(5))

	//P.Copy(W[(w[nb]-1)/2])
	P.selector(W, int32(w[nb]))
	for i := nb - 1; i >= 0; i-- {
		Q.selector(W, int32(w[i]))
		P.Dbl(mem)
		P.Dbl(mem)
		P.Dbl(mem)
		P.Dbl(mem)
		P.Add(Q, mem)
	}
	P.Sub(C, mem)
	P.Affine(mem)
	return P
}

/* Public version */
func (E *ECP8) Mul(e *BIG, mem *arena.Arena) *ECP8 {
	return E.mul(e, mem)
}

/* needed for SOK */
func (E *ECP8) Cfp() {

	F := ECP8_frob_constants()
	x := NewBIGints(CURVE_Bnx, nil)

	xQ := E.Mul(x, nil)
	x2Q := xQ.Mul(x, nil)
	x3Q := x2Q.Mul(x, nil)
	x4Q := x3Q.Mul(x, nil)
	x5Q := x4Q.Mul(x, nil)
	x6Q := x5Q.Mul(x, nil)
	x7Q := x6Q.Mul(x, nil)
	x8Q := x7Q.Mul(x, nil)

	xQ.Neg(nil)
	x3Q.Neg(nil)
	x5Q.Neg(nil)
	x7Q.Neg(nil)

	x8Q.Sub(x7Q, nil)
	x8Q.Sub(E, nil)

	x7Q.Sub(x6Q, nil)
	x7Q.frob(F, 1)

	x6Q.Sub(x5Q, nil)
	x6Q.frob(F, 2)

	x5Q.Sub(x4Q, nil)
	x5Q.frob(F, 3)

	x4Q.Sub(x3Q, nil)
	x4Q.frob(F, 4)

	x3Q.Sub(x2Q, nil)
	x3Q.frob(F, 5)

	x2Q.Sub(xQ, nil)
	x2Q.frob(F, 6)

	xQ.Sub(E, nil)
	xQ.frob(F, 7)

	E.Dbl(nil)
	E.frob(F, 8)

	E.Add(x8Q, nil)
	E.Add(x7Q, nil)
	E.Add(x6Q, nil)
	E.Add(x5Q, nil)

	E.Add(x4Q, nil)
	E.Add(x3Q, nil)
	E.Add(x2Q, nil)
	E.Add(xQ, nil)

	E.Affine(nil)
}

func ECP8_generator() *ECP8 {
	var G *ECP8
	G = NewECP8fp8s(
		NewFP8fp4s(
			NewFP4fp2s(
				NewFP2bigs(NewBIGints(CURVE_Pxaaa, nil), NewBIGints(CURVE_Pxaab, nil), nil),
				NewFP2bigs(NewBIGints(CURVE_Pxaba, nil), NewBIGints(CURVE_Pxabb, nil), nil), nil),
			NewFP4fp2s(
				NewFP2bigs(NewBIGints(CURVE_Pxbaa, nil), NewBIGints(CURVE_Pxbab, nil), nil),
				NewFP2bigs(NewBIGints(CURVE_Pxbba, nil), NewBIGints(CURVE_Pxbbb, nil), nil), nil), nil),
		NewFP8fp4s(
			NewFP4fp2s(
				NewFP2bigs(NewBIGints(CURVE_Pyaaa, nil), NewBIGints(CURVE_Pyaab, nil), nil),
				NewFP2bigs(NewBIGints(CURVE_Pyaba, nil), NewBIGints(CURVE_Pyabb, nil), nil), nil),
			NewFP4fp2s(
				NewFP2bigs(NewBIGints(CURVE_Pybaa, nil), NewBIGints(CURVE_Pybab, nil), nil),
				NewFP2bigs(NewBIGints(CURVE_Pybba, nil), NewBIGints(CURVE_Pybbb, nil), nil), nil), nil), nil)
	return G
}

func ECP8_hap2point(h *BIG) *ECP8 {
	one := NewBIGint(1, nil)
	x := NewBIGcopy(h, nil)
	var X2 *FP2
	var X4 *FP4
	var X8 *FP8
	var Q *ECP8
	for true {
		X2 = NewFP2bigs(one, x, nil)
		X4 = NewFP4fp2(X2, nil)
		X8 = NewFP8fp4(X4, nil)
		Q = NewECP8fp8(X8, 0, nil)
		if !Q.Is_infinity(nil) {
			break
		}
		x.inc(1)
		x.norm()
	}
	return Q
}

/* Deterministic mapping of Fp to point on curve */
func ECP8_map2point(H *FP8) *ECP8 {
	// Shallue and van de Woestijne
	NY := NewFP8int(1, nil)
	T := NewFP8copy(H, nil)
	sgn := T.sign(nil)

	Z := NewFPint(RIADZG2A, nil)
	X1 := NewFP8fp(Z, nil)
	X3 := NewFP8copy(X1, nil)
	A := RHS8(X1, nil)
	W := NewFP8copy(A, nil)
	W.Sqrt(nil, nil)

	s := NewFPbig(NewBIGints(SQRTm3, nil), nil)
	Z.Mul(s, nil)

	T.Sqr(nil)
	Y := NewFP8copy(A, nil)
	Y.Mul(T, nil)
	T.copy(NY)
	T.Add(Y, nil)
	T.norm()
	Y.rsub(NY, nil)
	Y.norm()
	NY.copy(T)
	NY.Mul(Y, nil)

	NY.tmul(Z, nil)
	NY.Invert(nil, nil)

	W.tmul(Z, nil)
	if W.sign(nil) == 1 {
		W.Neg(nil)
		W.norm()
	}
	W.tmul(Z, nil)
	W.Mul(H, nil)
	W.Mul(Y, nil)
	W.Mul(NY, nil)

	X1.Neg(nil)
	X1.norm()
	X1.div2(nil)
	X2 := NewFP8copy(X1, nil)
	X1.Sub(W, nil)
	X1.norm()
	X2.Add(W, nil)
	X2.norm()
	A.Add(A, nil)
	A.Add(A, nil)
	A.norm()
	T.Sqr(nil)
	T.Mul(NY, nil)
	T.Sqr(nil)
	A.Mul(T, nil)
	X3.Add(A, nil)
	X3.norm()

	Y.copy(RHS8(X2, nil))
	X3.cmove(X2, Y.qr(nil))
	Y.copy(RHS8(X1, nil))
	X3.cmove(X1, Y.qr(nil))
	Y.copy(RHS8(X3, nil))
	Y.Sqrt(nil, nil)

	ne := Y.sign(nil) ^ sgn
	W.copy(Y)
	W.Neg(nil)
	W.norm()
	Y.cmove(W, ne)

	return NewECP8fp8s(X3, Y, nil)
}

/* Map octet string to curve point */
func ECP8_mapit(h []byte) *ECP8 {
	q := NewBIGints(Modulus, nil)
	dx := DBIG_fromBytes(h)
	x := dx.Mod(q, nil)

	Q := ECP8_hap2point(x)
	Q.Cfp()
	return Q
}

/* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3.. */
// Bos & Costello https://eprint.iacr.org/2013/458.pdf
// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
// Side channel attack secure
func Mul16(Q []*ECP8, u []*BIG, mem *arena.Arena) *ECP8 {
	W := NewECP8(mem)
	P := NewECP8(mem)
	var T1 []*ECP8
	var T2 []*ECP8
	var T3 []*ECP8
	var T4 []*ECP8
	mt := NewBIG(mem)
	var t []*BIG
	var bt int8
	var k int

	var w1 [NLEN*int(BASEBITS) + 1]int8
	var s1 [NLEN*int(BASEBITS) + 1]int8
	var w2 [NLEN*int(BASEBITS) + 1]int8
	var s2 [NLEN*int(BASEBITS) + 1]int8
	var w3 [NLEN*int(BASEBITS) + 1]int8
	var s3 [NLEN*int(BASEBITS) + 1]int8
	var w4 [NLEN*int(BASEBITS) + 1]int8
	var s4 [NLEN*int(BASEBITS) + 1]int8

	for i := 0; i < 16; i++ {
		t = append(t, NewBIGcopy(u[i], mem))
	}

	T1 = append(T1, NewECP8(mem))
	T1[0].Copy(Q[0]) // Q[0]
	T1 = append(T1, NewECP8(mem))
	T1[1].Copy(T1[0])
	T1[1].Add(Q[1], mem) // Q[0]+Q[1]
	T1 = append(T1, NewECP8(mem))
	T1[2].Copy(T1[0])
	T1[2].Add(Q[2], mem) // Q[0]+Q[2]
	T1 = append(T1, NewECP8(mem))
	T1[3].Copy(T1[1])
	T1[3].Add(Q[2], mem) // Q[0]+Q[1]+Q[2]
	T1 = append(T1, NewECP8(mem))
	T1[4].Copy(T1[0])
	T1[4].Add(Q[3], mem) // Q[0]+Q[3]
	T1 = append(T1, NewECP8(mem))
	T1[5].Copy(T1[1])
	T1[5].Add(Q[3], mem) // Q[0]+Q[1]+Q[3]
	T1 = append(T1, NewECP8(mem))
	T1[6].Copy(T1[2])
	T1[6].Add(Q[3], mem) // Q[0]+Q[2]+Q[3]
	T1 = append(T1, NewECP8(mem))
	T1[7].Copy(T1[3])
	T1[7].Add(Q[3], mem) // Q[0]+Q[1]+Q[2]+Q[3]

	T2 = append(T2, NewECP8(mem))
	T2[0].Copy(Q[4]) // Q[0]
	T2 = append(T2, NewECP8(mem))
	T2[1].Copy(T2[0])
	T2[1].Add(Q[5], mem) // Q[0]+Q[1]
	T2 = append(T2, NewECP8(mem))
	T2[2].Copy(T2[0])
	T2[2].Add(Q[6], mem) // Q[0]+Q[2]
	T2 = append(T2, NewECP8(mem))
	T2[3].Copy(T2[1])
	T2[3].Add(Q[6], mem) // Q[0]+Q[1]+Q[2]
	T2 = append(T2, NewECP8(mem))
	T2[4].Copy(T2[0])
	T2[4].Add(Q[7], mem) // Q[0]+Q[3]
	T2 = append(T2, NewECP8(mem))
	T2[5].Copy(T2[1])
	T2[5].Add(Q[7], mem) // Q[0]+Q[1]+Q[3]
	T2 = append(T2, NewECP8(mem))
	T2[6].Copy(T2[2])
	T2[6].Add(Q[7], mem) // Q[0]+Q[2]+Q[3]
	T2 = append(T2, NewECP8(mem))
	T2[7].Copy(T2[3])
	T2[7].Add(Q[7], mem) // Q[0]+Q[1]+Q[2]+Q[3]

	T3 = append(T3, NewECP8(mem))
	T3[0].Copy(Q[8]) // Q[0]
	T3 = append(T3, NewECP8(mem))
	T3[1].Copy(T3[0])
	T3[1].Add(Q[9], mem) // Q[0]+Q[1]
	T3 = append(T3, NewECP8(mem))
	T3[2].Copy(T3[0])
	T3[2].Add(Q[10], mem) // Q[0]+Q[2]
	T3 = append(T3, NewECP8(mem))
	T3[3].Copy(T3[1])
	T3[3].Add(Q[10], mem) // Q[0]+Q[1]+Q[2]
	T3 = append(T3, NewECP8(mem))
	T3[4].Copy(T3[0])
	T3[4].Add(Q[11], mem) // Q[0]+Q[3]
	T3 = append(T3, NewECP8(mem))
	T3[5].Copy(T3[1])
	T3[5].Add(Q[11], mem) // Q[0]+Q[1]+Q[3]
	T3 = append(T3, NewECP8(mem))
	T3[6].Copy(T3[2])
	T3[6].Add(Q[11], mem) // Q[0]+Q[2]+Q[3]
	T3 = append(T3, NewECP8(mem))
	T3[7].Copy(T3[3])
	T3[7].Add(Q[11], mem) // Q[0]+Q[1]+Q[2]+Q[3]

	T4 = append(T4, NewECP8(mem))
	T4[0].Copy(Q[12]) // Q[0]
	T4 = append(T4, NewECP8(mem))
	T4[1].Copy(T4[0])
	T4[1].Add(Q[13], mem) // Q[0]+Q[1]
	T4 = append(T4, NewECP8(mem))
	T4[2].Copy(T4[0])
	T4[2].Add(Q[14], mem) // Q[0]+Q[2]
	T4 = append(T4, NewECP8(mem))
	T4[3].Copy(T4[1])
	T4[3].Add(Q[14], mem) // Q[0]+Q[1]+Q[2]
	T4 = append(T4, NewECP8(mem))
	T4[4].Copy(T4[0])
	T4[4].Add(Q[15], mem) // Q[0]+Q[3]
	T4 = append(T4, NewECP8(mem))
	T4[5].Copy(T4[1])
	T4[5].Add(Q[15], mem) // Q[0]+Q[1]+Q[3]
	T4 = append(T4, NewECP8(mem))
	T4[6].Copy(T4[2])
	T4[6].Add(Q[15], mem) // Q[0]+Q[2]+Q[3]
	T4 = append(T4, NewECP8(mem))
	T4[7].Copy(T4[3])
	T4[7].Add(Q[15], mem) // Q[0]+Q[1]+Q[2]+Q[3]

	// Make them odd
	pb1 := 1 - t[0].parity()
	t[0].inc(pb1)

	pb2 := 1 - t[4].parity()
	t[4].inc(pb2)

	pb3 := 1 - t[8].parity()
	t[8].inc(pb3)

	pb4 := 1 - t[12].parity()
	t[12].inc(pb4)

	// Number of bits
	mt.zero()
	for i := 0; i < 16; i++ {
		t[i].norm()
		mt.or(t[i])
	}

	nb := 1 + mt.nbits()

	// Sign pivot
	s1[nb-1] = 1
	s2[nb-1] = 1
	s3[nb-1] = 1
	s4[nb-1] = 1
	for i := 0; i < nb-1; i++ {
		t[0].fshr(1)
		s1[i] = 2*int8(t[0].parity()) - 1
		t[4].fshr(1)
		s2[i] = 2*int8(t[4].parity()) - 1
		t[8].fshr(1)
		s3[i] = 2*int8(t[8].parity()) - 1
		t[12].fshr(1)
		s4[i] = 2*int8(t[12].parity()) - 1

	}

	// Recoded exponents
	for i := 0; i < nb; i++ {
		w1[i] = 0
		k = 1
		for j := 1; j < 4; j++ {
			bt = s1[i] * int8(t[j].parity())
			t[j].fshr(1)
			t[j].dec(int(bt) >> 1)
			t[j].norm()
			w1[i] += bt * int8(k)
			k *= 2
		}
		w2[i] = 0
		k = 1
		for j := 5; j < 8; j++ {
			bt = s2[i] * int8(t[j].parity())
			t[j].fshr(1)
			t[j].dec(int(bt) >> 1)
			t[j].norm()
			w2[i] += bt * int8(k)
			k *= 2
		}
		w3[i] = 0
		k = 1
		for j := 9; j < 12; j++ {
			bt = s3[i] * int8(t[j].parity())
			t[j].fshr(1)
			t[j].dec(int(bt) >> 1)
			t[j].norm()
			w3[i] += bt * int8(k)
			k *= 2
		}
		w4[i] = 0
		k = 1
		for j := 13; j < 16; j++ {
			bt = s4[i] * int8(t[j].parity())
			t[j].fshr(1)
			t[j].dec(int(bt) >> 1)
			t[j].norm()
			w4[i] += bt * int8(k)
			k *= 2
		}
	}

	// Main loop
	P.selector(T1, int32(2*w1[nb-1]+1))
	W.selector(T2, int32(2*w2[nb-1]+1))
	P.Add(W, mem)
	W.selector(T3, int32(2*w3[nb-1]+1))
	P.Add(W, mem)
	W.selector(T4, int32(2*w4[nb-1]+1))
	P.Add(W, mem)
	for i := nb - 2; i >= 0; i-- {
		P.Dbl(mem)
		W.selector(T1, int32(2*w1[i]+s1[i]))
		P.Add(W, mem)
		W.selector(T2, int32(2*w2[i]+s2[i]))
		P.Add(W, mem)
		W.selector(T3, int32(2*w3[i]+s3[i]))
		P.Add(W, mem)
		W.selector(T4, int32(2*w4[i]+s4[i]))
		P.Add(W, mem)

	}

	// apply correction
	W.Copy(P)
	W.Sub(Q[0], mem)
	P.cmove(W, pb1)
	W.Copy(P)
	W.Sub(Q[4], mem)
	P.cmove(W, pb2)
	W.Copy(P)
	W.Sub(Q[8], mem)
	P.cmove(W, pb3)
	W.Copy(P)
	W.Sub(Q[12], mem)
	P.cmove(W, pb4)

	P.Affine(mem)
	return P
}
