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

package bls48581

import "arena"

//import "fmt"
/* Elliptic Curve Point Structure */

type ECP struct {
	x *FP
	y *FP
	z *FP
}

/* Constructors */
func NewECP(mem *arena.Arena) *ECP {
	var E *ECP
	if mem != nil {
		E = arena.New[ECP](mem)
	} else {
		E = new(ECP)
	}
	E.x = NewFP(mem)
	E.y = NewFPint(1, mem)
	E.z = NewFP(mem)
	return E
}

/* set (x,y) from two BIGs */
func NewECPbigs(ix *BIG, iy *BIG, mem *arena.Arena) *ECP {
	var E *ECP
	if mem != nil {
		E = arena.New[ECP](mem)
	} else {
		E = new(ECP)
	}
	E.x = NewFPbig(ix, mem)
	E.y = NewFPbig(iy, mem)
	E.z = NewFPint(1, mem)
	E.x.norm()
	rhs := RHS(E.x, mem)

	y2 := NewFPcopy(E.y, mem)
	y2.Sqr(mem)
	if !y2.Equals(rhs) {
		E.inf()
	}
	return E
}

/* set (x,y) from BIG and a bit */
func NewECPbigint(ix *BIG, s int, mem *arena.Arena) *ECP {
	var E *ECP
	if mem != nil {
		E = arena.New[ECP](mem)
	} else {
		E = new(ECP)
	}
	E.x = NewFPbig(ix, mem)
	E.y = NewFP(mem)
	E.x.norm()
	rhs := RHS(E.x, mem)
	E.z = NewFPint(1, mem)
	hint := NewFP(mem)
	if rhs.qr(hint) == 1 {
		ny := rhs.Sqrt(hint, mem)
		if ny.sign(mem) != s {
			ny.Neg(mem)
			ny.norm()
		}
		E.y.copy(ny)
	} else {
		E.inf()
	}
	return E
}

/* set from x - calculate y from curve equation */
func NewECPbig(ix *BIG, mem *arena.Arena) *ECP {
	var E *ECP
	if mem != nil {
		E = arena.New[ECP](mem)
	} else {
		E = new(ECP)
	}
	E.x = NewFPbig(ix, mem)
	E.y = NewFP(mem)
	E.x.norm()
	rhs := RHS(E.x, mem)
	E.z = NewFPint(1, mem)
	hint := NewFP(mem)
	if rhs.qr(hint) == 1 {
		E.y.copy(rhs.Sqrt(hint, mem))
	} else {
		E.inf()
	}
	return E
}

/* test for O point-at-infinity */
func (E *ECP) Is_infinity(mem *arena.Arena) bool {
	//	if E.INF {return true}

	return (E.x.IsZero(mem) && E.z.IsZero(mem))
}

/* Conditional swap of P and Q dependant on d */
func (E *ECP) cswap(Q *ECP, d int) {
	E.x.cswap(Q.x, d)
	E.y.cswap(Q.y, d)
	E.z.cswap(Q.z, d)
}

/* Conditional move of Q to P dependant on d */
func (E *ECP) cmove(Q *ECP, d int) {
	E.x.cmove(Q.x, d)
	E.y.cmove(Q.y, d)
	E.z.cmove(Q.z, d)
}

/* return 1 if b==c, no branching */
func teq(b int32, c int32) int {
	x := b ^ c
	x -= 1 // if x=0, x now -1
	return int((x >> 31) & 1)
}

/* this=P */
func (E *ECP) Copy(P *ECP) {
	E.x.copy(P.x)
	E.y.copy(P.y)
	E.z.copy(P.z)
}

/* this=-this */
func (E *ECP) Neg(mem *arena.Arena) {
	E.y.Neg(mem)
	E.y.norm()
	return
}

/* Constant time select from pre-computed table */
func (E *ECP) selector(W []*ECP, b int32) {
	MP := NewECP(nil)
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

/* set this=O */
func (E *ECP) inf() {
	E.x.zero()
	E.y.one()
	E.z.zero()
}

/* Test P == Q */
func (E *ECP) Equals(Q *ECP) bool {
	mem := arena.NewArena()
	defer mem.Free()
	a := NewFP(mem)
	b := NewFP(mem)
	a.copy(E.x)
	a.Mul(Q.z, mem)
	a.reduce(mem)
	b.copy(Q.x)
	b.Mul(E.z, mem)
	b.reduce(mem)
	if !a.Equals(b) {
		return false
	}
	a.copy(E.y)
	a.Mul(Q.z, mem)
	a.reduce(mem)
	b.copy(Q.y)
	b.Mul(E.z, mem)
	b.reduce(mem)
	if !a.Equals(b) {
		return false
	}

	return true
}

/* Calculate RHS of curve equation */
func RHS(x *FP, mem *arena.Arena) *FP {
	r := NewFPcopy(x, mem)
	r.Sqr(mem)

	// x^3+Ax+B
	b := NewFPbig(NewBIGints(CURVE_B, mem), mem)
	r.Mul(x, mem)
	if CURVE_A == -3 {
		cx := NewFPcopy(x, mem)
		cx.imul(3, mem)
		cx.Neg(mem)
		cx.norm()
		r.Add(cx, mem)
	}
	r.Add(b, mem)

	r.reduce(mem)
	return r
}

/* set to affine - from (x,y,z) to (x,y) */
func (E *ECP) Affine(mem *arena.Arena) {
	if E.Is_infinity(mem) {
		return
	}
	one := NewFPint(1, mem)
	if E.z.Equals(one) {
		return
	}
	E.z.Invert(nil, mem)
	E.x.Mul(E.z, mem)
	E.x.reduce(mem)

	E.y.Mul(E.z, mem)
	E.y.reduce(mem)
	E.z.copy(one)
}

/* extract x as a BIG */
func (E *ECP) GetX(mem *arena.Arena) *BIG {
	W := NewECP(mem)
	W.Copy(E)
	W.Affine(mem)
	return W.x.Redc(mem)
}

/* extract y as a BIG */
func (E *ECP) GetY(mem *arena.Arena) *BIG {
	W := NewECP(mem)
	W.Copy(E)
	W.Affine(mem)
	return W.y.Redc(mem)
}

/* get sign of Y */
func (E *ECP) GetS(mem *arena.Arena) int {
	W := NewECP(mem)
	W.Copy(E)
	W.Affine(mem)
	return W.y.sign(mem)
}

/* extract x as an FP */
func (E *ECP) getx() *FP {
	return E.x
}

/* extract y as an FP */
func (E *ECP) gety() *FP {
	return E.y
}

/* extract z as an FP */
func (E *ECP) getz() *FP {
	return E.z
}

/* convert to byte array */
func (E *ECP) ToBytes(b []byte, compress bool) {
	var t [int(MODBYTES)]byte
	MB := int(MODBYTES)
	W := NewECP(nil)
	W.Copy(E)
	W.Affine(nil)
	W.x.Redc(nil).ToBytes(t[:])

	for i := 0; i < MB; i++ {
		b[i+1] = t[i]
	}
	if compress {
		b[0] = 0x02
		if W.y.sign(nil) == 1 {
			b[0] = 0x03
		}
		return
	}
	b[0] = 0x04
	W.y.Redc(nil).ToBytes(t[:])
	for i := 0; i < MB; i++ {
		b[i+MB+1] = t[i]
	}
}

/* convert from byte array to point */
func ECP_fromBytes(b []byte) *ECP {
	var t [int(MODBYTES)]byte
	MB := int(MODBYTES)
	p := NewBIGints(Modulus, nil)

	for i := 0; i < MB; i++ {
		t[i] = b[i+1]
	}
	px := FromBytes(t[:])
	if Comp(px, p) >= 0 {
		return NewECP(nil)
	}

	if b[0] == 0x04 {
		for i := 0; i < MB; i++ {
			t[i] = b[i+MB+1]
		}
		py := FromBytes(t[:])
		if Comp(py, p) >= 0 {
			return NewECP(nil)
		}
		return NewECPbigs(px, py, nil)
	}

	if b[0] == 0x02 || b[0] == 0x03 {
		return NewECPbigint(px, int(b[0]&1), nil)
	}
	return NewECP(nil)
}

/* convert to hex string */
func (E *ECP) ToString() string {
	W := NewECP(nil)
	W.Copy(E)
	W.Affine(nil)
	if W.Is_infinity(nil) {
		return "infinity"
	}
	return "(" + W.x.Redc(nil).ToString() + "," + W.y.Redc(nil).ToString() + ")"
}

/* this*=2 */
func (E *ECP) Dbl(mem *arena.Arena) {
	t0 := NewFPcopy(E.y, mem)
	t0.Sqr(mem)
	t1 := NewFPcopy(E.y, mem)
	t1.Mul(E.z, mem)
	t2 := NewFPcopy(E.z, mem)
	t2.Sqr(mem)

	E.z.copy(t0)
	E.z.Add(t0, mem)
	E.z.norm()
	E.z.Add(E.z, mem)
	E.z.Add(E.z, mem)
	E.z.norm()
	t2.imul(3*CURVE_B_I, mem)

	x3 := NewFPcopy(t2, mem)
	x3.Mul(E.z, mem)

	y3 := NewFPcopy(t0, mem)
	y3.Add(t2, mem)
	y3.norm()
	E.z.Mul(t1, mem)
	t1.copy(t2)
	t1.Add(t2, mem)
	t2.Add(t1, mem)
	t0.Sub(t2, mem)
	t0.norm()
	y3.Mul(t0, mem)
	y3.Add(x3, mem)
	t1.copy(E.x)
	t1.Mul(E.y, mem)
	E.x.copy(t0)
	E.x.norm()
	E.x.Mul(t1, mem)
	E.x.Add(E.x, mem)
	E.x.norm()
	E.y.copy(y3)
	E.y.norm()

	return
}

/* this+=Q */
func (E *ECP) Add(Q *ECP, mem *arena.Arena) {
	b := 3 * CURVE_B_I
	t0 := NewFPcopy(E.x, mem)
	t0.Mul(Q.x, mem)
	t1 := NewFPcopy(E.y, mem)
	t1.Mul(Q.y, mem)
	t2 := NewFPcopy(E.z, mem)
	t2.Mul(Q.z, mem)
	t3 := NewFPcopy(E.x, mem)
	t3.Add(E.y, mem)
	t3.norm()
	t4 := NewFPcopy(Q.x, mem)
	t4.Add(Q.y, mem)
	t4.norm()
	t3.Mul(t4, mem)
	t4.copy(t0)
	t4.Add(t1, mem)

	t3.Sub(t4, mem)
	t3.norm()
	t4.copy(E.y)
	t4.Add(E.z, mem)
	t4.norm()
	x3 := NewFPcopy(Q.y, mem)
	x3.Add(Q.z, mem)
	x3.norm()

	t4.Mul(x3, mem)
	x3.copy(t1)
	x3.Add(t2, mem)

	t4.Sub(x3, mem)
	t4.norm()
	x3.copy(E.x)
	x3.Add(E.z, mem)
	x3.norm()
	y3 := NewFPcopy(Q.x, mem)
	y3.Add(Q.z, mem)
	y3.norm()
	x3.Mul(y3, mem)
	y3.copy(t0)
	y3.Add(t2, mem)
	y3.rsub(x3, mem)
	y3.norm()
	x3.copy(t0)
	x3.Add(t0, mem)
	t0.Add(x3, mem)
	t0.norm()
	t2.imul(b, mem)

	z3 := NewFPcopy(t1, mem)
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

	return
}

/* this-=Q */
func (E *ECP) Sub(Q *ECP, mem *arena.Arena) {
	NQ := NewECP(mem)
	NQ.Copy(Q)
	NQ.Neg(mem)
	E.Add(NQ, mem)
}

/* constant time multiply by small integer of length bts - use lAdder */
func (E *ECP) pinmul(e int32, bts int32, mem *arena.Arena) *ECP {
	P := NewECP(mem)
	R0 := NewECP(mem)
	R1 := NewECP(mem)
	R1.Copy(E)

	for i := bts - 1; i >= 0; i-- {
		b := int((e >> uint32(i)) & 1)
		P.Copy(R1)
		P.Add(R0, mem)
		R0.cswap(R1, b)
		R1.Copy(P)
		R0.Dbl(mem)
		R0.cswap(R1, b)
	}
	P.Copy(R0)
	return P
}

// Point multiplication, multiplies a point P by a scalar e
// This code has no inherent awareness of the order of the curve, or the order of the point.
// The order of the curve will be h.r, where h is a cofactor, and r is a large prime
// Typically P will be of order r (but not always), and typically e will be less than r (but not always)
// A problem can arise if a secret e is a few bits less than r, as the leading zeros in e will leak via a timing attack
// The secret e may however be greater than r (see RFC7748 which combines elimination of a small cofactor h with the point multiplication, using an e>r)
// Our solution is to use as a multiplier an e, whose length in bits is that of the logical OR of e and r, hence allowing e>r while forcing inclusion of leading zeros if e<r.
// The point multiplication methods used will process leading zeros correctly.

// So this function leaks information about the length of e...
func (E *ECP) lmul(e *BIG, outer, mem *arena.Arena) *ECP {
	return E.clmul(e, e, outer, mem)
}

// .. but this one does not (typically set maxe=r)
// Set P=e*P
/* return e.this */
func (E *ECP) clmul(e *BIG, maxe *BIG, outer, mem *arena.Arena) *ECP {
	if e.IsZero() || E.Is_infinity(mem) {
		return NewECP(outer)
	}
	P := NewECP(outer)
	cm := NewBIGcopy(e, mem)
	cm.or(maxe)
	max := cm.nbits()

	// fixed size windows
	mt := NewBIG(mem)
	t := NewBIG(mem)
	Q := NewECP(mem)
	C := NewECP(mem)

	var W []*ECP
	var w [1 + (NLEN*int(BASEBITS)+3)/4]int8

	Q.Copy(E)
	Q.Dbl(mem)

	W = append(W, NewECP(mem))
	W[0].Copy(E)

	for i := 1; i < 8; i++ {
		W = append(W, NewECP(mem))
		W[i].Copy(W[i-1])
		W[i].Add(Q, mem)
	}

	// make exponent odd - Add 2P if even, P if odd
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

	nb := 1 + (max+3)/4

	// convert exponent to signed 4-bit window
	for i := 0; i < nb; i++ {
		w[i] = int8(t.lastbits(5) - 16)
		t.dec(int(w[i]))
		t.norm()
		t.fshr(4)
	}
	w[nb] = int8(t.lastbits(5))

	//P.Copy(W[(int(w[nb])-1)/2])
	P.selector(W, int32(w[nb]))
	for i := nb - 1; i >= 0; i-- {
		Q.selector(W, int32(w[i]))
		P.Dbl(mem)
		P.Dbl(mem)
		P.Dbl(mem)
		P.Dbl(mem)
		P.Add(Q, mem)
	}
	P.Sub(C, mem) /* apply correction */
	return P
}

/* Public version */
func (E *ECP) Mul(e *BIG, outer, mem *arena.Arena) *ECP {
	return E.lmul(e, outer, mem)
}

// Generic multi-multiplication, fixed 4-bit window, P=Sigma e_i*X_i
func ECP_muln(n int, X []*ECP, e []*BIG, mem *arena.Arena) *ECP {
	P := NewECP(nil)
	R := NewECP(mem)
	S := NewECP(mem)
	var B []*ECP
	t := NewBIG(mem)
	for i := 0; i < 16; i++ {
		B = append(B, NewECP(mem))
	}
	mt := NewBIGcopy(e[0], mem)
	mt.norm()
	for i := 1; i < n; i++ { // find biggest
		t.copy(e[i])
		t.norm()
		k := Comp(t, mt)
		mt.cmove(t, (k+1)/2)
	}
	nb := (mt.nbits() + 3) / 4
	for i := nb - 1; i >= 0; i-- {
		for j := 0; j < 16; j++ {
			B[j].inf()
		}

		inner := arena.NewArena()
		for j := 0; j < n; j++ {
			mt.copy(e[j])
			mt.norm()
			mt.shr(uint(i * 4))
			k := mt.lastbits(4)
			B[k].Add(X[j], inner)
			if j%32 == 0 || j == n-1 {
				inner.Free()
				inner = arena.NewArena()
			}
		}
		R.inf()
		S.inf()
		for j := 15; j >= 1; j-- {
			R.Add(B[j], mem)
			S.Add(R, mem)
		}
		for j := 0; j < 4; j++ {
			P.Dbl(mem)
		}
		P.Add(S, mem)
	}
	return P
}

/* Return e.this+f.Q */

func (E *ECP) Mul2(e *BIG, Q *ECP, f *BIG, mem *arena.Arena) *ECP {
	te := NewBIG(mem)
	tf := NewBIG(mem)
	mt := NewBIG(mem)
	S := NewECP(mem)
	T := NewECP(mem)
	C := NewECP(mem)
	var W []*ECP
	var w [1 + (NLEN*int(BASEBITS)+1)/2]int8

	te.copy(e)
	tf.copy(f)

	// precompute table
	for i := 0; i < 8; i++ {
		W = append(W, NewECP(mem))
	}
	W[1].Copy(E)
	W[1].Sub(Q, mem)
	W[2].Copy(E)
	W[2].Add(Q, mem)
	S.Copy(Q)
	S.Dbl(mem)
	W[0].Copy(W[1])
	W[0].Sub(S, mem)
	W[3].Copy(W[2])
	W[3].Add(S, mem)
	T.Copy(E)
	T.Dbl(mem)
	W[5].Copy(W[1])
	W[5].Add(T, mem)
	W[6].Copy(W[2])
	W[6].Add(T, mem)
	W[4].Copy(W[5])
	W[4].Sub(S, mem)
	W[7].Copy(W[6])
	W[7].Add(S, mem)

	// if multiplier is odd, Add 2, else Add 1 to multiplier, and Add 2P or P to correction

	s := int(te.parity())
	te.inc(1)
	te.norm()
	ns := int(te.parity())
	mt.copy(te)
	mt.inc(1)
	mt.norm()
	te.cmove(mt, s)
	T.cmove(E, ns)
	C.Copy(T)

	s = int(tf.parity())
	tf.inc(1)
	tf.norm()
	ns = int(tf.parity())
	mt.copy(tf)
	mt.inc(1)
	mt.norm()
	tf.cmove(mt, s)
	S.cmove(Q, ns)
	C.Add(S, mem)

	mt.copy(te)
	mt.Add(tf)
	mt.norm()
	nb := 1 + (mt.nbits()+1)/2

	// convert exponent to signed 2-bit window
	for i := 0; i < nb; i++ {
		a := (te.lastbits(3) - 4)
		te.dec(int(a))
		te.norm()
		te.fshr(2)
		b := (tf.lastbits(3) - 4)
		tf.dec(int(b))
		tf.norm()
		tf.fshr(2)
		w[i] = int8(4*a + b)
	}
	w[nb] = int8(4*te.lastbits(3) + tf.lastbits(3))
	//S.Copy(W[(w[nb]-1)/2])
	S.selector(W, int32(w[nb]))
	for i := nb - 1; i >= 0; i-- {
		T.selector(W, int32(w[i]))
		S.Dbl(mem)
		S.Dbl(mem)
		S.Add(T, mem)
	}
	S.Sub(C, mem) /* apply correction */
	return S
}

func (E *ECP) Cfp() {
	mem := arena.NewArena()
	defer mem.Free()
	c := NewBIGints(CURVE_Cof, mem)
	E.Copy(E.lmul(c, nil, mem))
}

/* Hunt and Peck a BIG to a curve point */
func ECP_hap2point(h *BIG, mem *arena.Arena) *ECP {
	var P *ECP
	x := NewBIGcopy(h, mem)

	for true {
		P = NewECPbigint(x, 0, mem)
		x.inc(1)
		x.norm()
		if !P.Is_infinity(mem) {
			break
		}
	}
	return P
}

/* Constant time Map to Point */
func ECP_map2point(h *FP) *ECP {
	P := NewECP(nil)

	// swu method
	A := NewFP(nil)
	B := NewFP(nil)
	X1 := NewFP(nil)
	X2 := NewFP(nil)
	X3 := NewFP(nil)
	one := NewFPint(1, nil)
	Y := NewFP(nil)
	D := NewFP(nil)
	t := NewFPcopy(h, nil)
	w := NewFP(nil)
	//Y3:=NewFP()
	sgn := t.sign(nil)

	// Shallue and van de Woestijne
	// SQRTm3 not available, so preprocess this out
	/* */
	Z := RIADZ
	X1.copy(NewFPint(Z, nil))
	X3.copy(X1)
	A.copy(RHS(X1, nil))
	B.copy(NewFPbig(NewBIGints(SQRTm3, nil), nil))
	B.imul(Z, nil)

	t.Sqr(nil)
	Y.copy(A)
	Y.Mul(t, nil)
	t.copy(one)
	t.Add(Y, nil)
	t.norm()
	Y.rsub(one, nil)
	Y.norm()
	D.copy(t)
	D.Mul(Y, nil)
	D.Mul(B, nil)

	w.copy(A)
	FP_tpo(D, w)

	w.Mul(B, nil)
	if w.sign(nil) == 1 {
		w.Neg(nil)
		w.norm()
	}

	w.Mul(B, nil)
	w.Mul(h, nil)
	w.Mul(Y, nil)
	w.Mul(D, nil)

	X1.Neg(nil)
	X1.norm()
	X1.div2(nil)
	X2.copy(X1)
	X1.Sub(w, nil)
	X1.norm()
	X2.Add(w, nil)
	X2.norm()
	A.Add(A, nil)
	A.Add(A, nil)
	A.norm()
	t.Sqr(nil)
	t.Mul(D, nil)
	t.Sqr(nil)
	A.Mul(t, nil)
	X3.Add(A, nil)
	X3.norm()

	rhs := RHS(X2, nil)
	X3.cmove(X2, rhs.qr(nil))
	rhs.copy(RHS(X1, nil))
	X3.cmove(X1, rhs.qr(nil))
	rhs.copy(RHS(X3, nil))
	Y.copy(rhs.Sqrt(nil, nil))

	ne := Y.sign(nil) ^ sgn
	w.copy(Y)
	w.Neg(nil)
	w.norm()
	Y.cmove(w, ne)

	x := X3.Redc(nil)
	y := Y.Redc(nil)
	P.Copy(NewECPbigs(x, y, nil))
	return P
	/* */
}

func ECP_mapit(h []byte) *ECP {
	q := NewBIGints(Modulus, nil)
	dx := DBIG_fromBytes(h[:])
	x := dx.Mod(q, nil)

	P := ECP_hap2point(x, nil)
	P.Cfp()
	return P
}

func ECP_generator() *ECP {
	var G *ECP

	gx := NewBIGints(CURVE_Gx, nil)
	gy := NewBIGints(CURVE_Gy, nil)
	G = NewECPbigs(gx, gy, nil)
	return G
}
