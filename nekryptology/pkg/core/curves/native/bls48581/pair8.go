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

/* BLS Curve Pairing functions */

package bls48581

import (
	"arena"
)

//import "fmt"

// Point doubling for pairings
func dbl(A *ECP8, AA *FP8, BB *FP8, CC *FP8, mem *arena.Arena) {
	CC.copy(A.getx())               //X
	YY := NewFP8copy(A.gety(), mem) //Y
	BB.copy(A.getz())               //Z
	AA.copy(YY)                     //Y
	AA.Mul(BB, mem)                 //YZ
	CC.Sqr(mem)                     //X^2
	YY.Sqr(mem)                     //Y^2
	BB.Sqr(mem)                     //Z^2

	AA.Add(AA, mem)
	AA.Neg(mem)
	AA.norm() //-2AA
	AA.times_i(mem)

	sb := 3 * CURVE_B_I
	BB.imul(sb, mem)
	CC.imul(3, mem)
	YY.times_i(mem)
	CC.times_i(mem)
	BB.Sub(YY, mem)
	BB.norm()

	A.Dbl(mem)
}

// Point addition for pairings
func add(A *ECP8, B *ECP8, AA *FP8, BB *FP8, CC *FP8, mem *arena.Arena) {
	AA.copy(A.getx())               // X1
	CC.copy(A.gety())               // Y1
	T1 := NewFP8copy(A.getz(), mem) // Z1
	BB.copy(A.getz())               // Z1

	T1.Mul(B.gety(), mem) // T1=Z1.Y2
	BB.Mul(B.getx(), mem) // T2=Z1.X2

	AA.Sub(BB, mem)
	AA.norm() // X1=X1-Z1.X2
	CC.Sub(T1, mem)
	CC.norm() // Y1=Y1-Z1.Y2

	T1.copy(AA) // T1=X1-Z1.X2

	T1.Mul(B.gety(), mem) // T1=(X1-Z1.X2).Y2

	BB.copy(CC)           // T2=Y1-Z1.Y2
	BB.Mul(B.getx(), mem) // T2=(Y1-Z1.Y2).X2
	BB.Sub(T1, mem)
	BB.norm() // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
	CC.Neg(mem)
	CC.norm() // Y1=-(Y1-Z1.Y2).Xs

	A.Add(B, mem)
}

func line(A *ECP8, B *ECP8, Qx *FP, Qy *FP, mem *arena.Arena) *FP48 {
	AA := NewFP8(mem)
	BB := NewFP8(mem)
	CC := NewFP8(mem)

	var a *FP16
	var b *FP16
	var c *FP16

	if A == B {
		dbl(A, AA, BB, CC, mem)
	} else {
		add(A, B, AA, BB, CC, mem)
	}
	CC.tmul(Qx, mem)
	AA.tmul(Qy, mem)

	a = NewFP16fp8s(AA, BB, mem)

	b = NewFP16fp8(CC, mem) // L(0,1) | L(0,0) | L(1,0)
	c = NewFP16(mem)

	r := NewFP48fp16s(a, b, c, mem)
	r.stype = FP_SPARSER
	return r
}

/* prepare ate parameter, n=6u+2 (BN) or n=u (BLS), n3=3*n */
func lbits(n3 *BIG, n *BIG, mem *arena.Arena) int {
	n.copy(NewBIGints(CURVE_Bnx, mem))
	n3.copy(n)
	n3.pmul(3)
	n3.norm()
	return n3.nbits()
}

/* prepare for multi-pairing */
func Initmp(mem *arena.Arena) []*FP48 {
	var r []*FP48
	for i := ATE_BITS - 1; i >= 0; i-- {
		r = append(r, NewFP48int(1, mem))
	}
	return r
}

/* basic Miller loop */
func Miller(r []*FP48, mem *arena.Arena) *FP48 {
	res := NewFP48int(1, mem)
	for i := ATE_BITS - 1; i >= 1; i-- {
		res.Sqr(mem)
		res.ssmul(r[i], mem)
		r[i].zero()
	}

	res.conj(mem)
	res.ssmul(r[0], mem)
	r[0].zero()
	return res
}

// Store precomputed line details in an FP8
func pack(AA *FP8, BB *FP8, CC *FP8) *FP16 {
	i := NewFP8copy(CC, nil)
	i.Invert(nil, nil)
	a := NewFP8copy(AA, nil)
	a.Mul(i, nil)
	b := NewFP8copy(BB, nil)
	b.Mul(i, nil)
	return NewFP16fp8s(a, b, nil)
}

// Unpack G2 line function details and include G1
func unpack(T *FP16, Qx *FP, Qy *FP) *FP48 {
	var a *FP16
	var b *FP16
	var c *FP16

	a = NewFP16copy(T, nil)
	a.geta().tmul(Qy, nil)
	t := NewFP8fp(Qx, nil)
	b = NewFP16fp8(t, nil)
	c = NewFP16(nil)
	v := NewFP48fp16s(a, b, c, nil)
	v.stype = FP_SPARSEST
	return v
}

func precomp(GV *ECP8) []*FP16 {
	n := NewBIG(nil)
	n3 := NewBIG(nil)
	AA := NewFP8(nil)
	BB := NewFP8(nil)
	CC := NewFP8(nil)
	var bt int
	P := NewECP8(nil)
	P.Copy(GV)

	A := NewECP8(nil)
	A.Copy(P)
	MP := NewECP8(nil)
	MP.Copy(P)
	MP.Neg(nil)

	nb := lbits(n3, n, nil)
	var T []*FP16

	for i := nb - 2; i >= 1; i-- {
		dbl(A, AA, BB, CC, nil)
		T = append(T, pack(AA, BB, CC))
		bt = n3.bit(i) - n.bit(i)
		if bt == 1 {
			add(A, P, AA, BB, CC, nil)
			T = append(T, pack(AA, BB, CC))
		}
		if bt == -1 {
			add(A, MP, AA, BB, CC, nil)
			T = append(T, pack(AA, BB, CC))
		}
	}
	return T
}

func Another_pc(r []*FP48, T []*FP16, QV *ECP) {
	n := NewBIG(nil)
	n3 := NewBIG(nil)
	var lv, lv2 *FP48
	var bt, j int

	if QV.Is_infinity(nil) {
		return
	}

	Q := NewECP(nil)
	Q.Copy(QV)
	Q.Affine(nil)
	Qx := NewFPcopy(Q.getx(), nil)
	Qy := NewFPcopy(Q.gety(), nil)

	nb := lbits(n3, n, nil)
	j = 0
	for i := nb - 2; i >= 1; i-- {
		lv = unpack(T[j], Qx, Qy)
		j += 1
		bt = n3.bit(i) - n.bit(i)
		if bt == 1 {
			lv2 = unpack(T[j], Qx, Qy)
			j += 1
			lv.smul(lv2, nil)
		}
		if bt == -1 {
			lv2 = unpack(T[j], Qx, Qy)
			j += 1
			lv.smul(lv2, nil)
		}
		r[i].ssmul(lv, nil)
	}
}

/* Accumulate another set of line functions for n-pairing */
func Another(r []*FP48, P1 *ECP8, Q1 *ECP, mem *arena.Arena) {
	n := NewBIG(mem)
	n3 := NewBIG(mem)
	var lv, lv2 *FP48

	if Q1.Is_infinity(mem) {
		return
	}
	// P is needed in affine form for line function, Q for (Qx,Qy) extraction
	P := NewECP8(mem)
	P.Copy(P1)
	Q := NewECP(mem)
	Q.Copy(Q1)

	P.Affine(mem)
	Q.Affine(mem)

	Qx := NewFPcopy(Q.getx(), mem)
	Qy := NewFPcopy(Q.gety(), mem)

	A := NewECP8(mem)
	A.Copy(P)

	MP := NewECP8(mem)
	MP.Copy(P)
	MP.Neg(mem)

	nb := lbits(n3, n, mem)

	for i := nb - 2; i >= 1; i-- {
		lv = line(A, A, Qx, Qy, mem)

		bt := n3.bit(i) - n.bit(i)
		if bt == 1 {
			lv2 = line(A, P, Qx, Qy, mem)
			lv.smul(lv2, mem)
		}
		if bt == -1 {
			lv2 = line(A, MP, Qx, Qy, mem)
			lv.smul(lv2, mem)
		}
		r[i].ssmul(lv, mem)
	}
}

/* Optimal R-ate pairing */
func Ate(P1 *ECP8, Q1 *ECP) *FP48 {
	n := NewBIG(nil)
	n3 := NewBIG(nil)
	var lv, lv2 *FP48

	if Q1.Is_infinity(nil) {
		return NewFP48int(1, nil)
	}

	P := NewECP8(nil)
	P.Copy(P1)
	P.Affine(nil)
	Q := NewECP(nil)
	Q.Copy(Q1)
	Q.Affine(nil)

	Qx := NewFPcopy(Q.getx(), nil)
	Qy := NewFPcopy(Q.gety(), nil)

	A := NewECP8(nil)
	r := NewFP48int(1, nil)

	A.Copy(P)
	NP := NewECP8(nil)
	NP.Copy(P)
	NP.Neg(nil)

	nb := lbits(n3, n, nil)

	for i := nb - 2; i >= 1; i-- {
		r.Sqr(nil)
		lv = line(A, A, Qx, Qy, nil)

		bt := n3.bit(i) - n.bit(i)
		if bt == 1 {
			lv2 = line(A, P, Qx, Qy, nil)
			lv.smul(lv2, nil)
		}
		if bt == -1 {
			lv2 = line(A, NP, Qx, Qy, nil)
			lv.smul(lv2, nil)
		}
		r.ssmul(lv, nil)
	}

	r.conj(nil)

	return r
}

/* Optimal R-ate double pairing e(P,Q).e(R,S) */
func Ate2(P1 *ECP8, Q1 *ECP, R1 *ECP8, S1 *ECP) *FP48 {
	n := NewBIG(nil)
	n3 := NewBIG(nil)
	var lv, lv2 *FP48

	if Q1.Is_infinity(nil) {
		return Ate(R1, S1)
	}
	if S1.Is_infinity(nil) {
		return Ate(P1, Q1)
	}

	P := NewECP8(nil)
	P.Copy(P1)
	P.Affine(nil)
	Q := NewECP(nil)
	Q.Copy(Q1)
	Q.Affine(nil)
	R := NewECP8(nil)
	R.Copy(R1)
	R.Affine(nil)
	S := NewECP(nil)
	S.Copy(S1)
	S.Affine(nil)

	Qx := NewFPcopy(Q.getx(), nil)
	Qy := NewFPcopy(Q.gety(), nil)
	Sx := NewFPcopy(S.getx(), nil)
	Sy := NewFPcopy(S.gety(), nil)

	A := NewECP8(nil)
	B := NewECP8(nil)
	r := NewFP48int(1, nil)

	A.Copy(P)
	B.Copy(R)
	NP := NewECP8(nil)
	NP.Copy(P)
	NP.Neg(nil)
	NR := NewECP8(nil)
	NR.Copy(R)
	NR.Neg(nil)

	nb := lbits(n3, n, nil)

	for i := nb - 2; i >= 1; i-- {
		r.Sqr(nil)
		lv = line(A, A, Qx, Qy, nil)
		lv2 = line(B, B, Sx, Sy, nil)
		lv.smul(lv2, nil)
		r.ssmul(lv, nil)
		bt := n3.bit(i) - n.bit(i)
		if bt == 1 {
			lv = line(A, P, Qx, Qy, nil)
			lv2 = line(B, R, Sx, Sy, nil)
			lv.smul(lv2, nil)
			r.ssmul(lv, nil)
		}
		if bt == -1 {
			lv = line(A, NP, Qx, Qy, nil)
			lv2 = line(B, NR, Sx, Sy, nil)
			lv.smul(lv2, nil)
			r.ssmul(lv, nil)
		}
	}

	r.conj(nil)

	return r
}

/* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
func Fexp(m *FP48) *FP48 {
	mem := arena.NewArena()
	f := NewFP2bigs(NewBIGints(Fra, mem), NewBIGints(Frb, mem), mem)
	x := NewBIGints(CURVE_Bnx, mem)
	r := NewFP48copy(m, nil)
	//	var t1, t2 *FP48

	/* Easy part of final exp */
	lv := NewFP48copy(r, mem)

	lv.Invert(mem)
	r.conj(mem)

	r.Mul(lv, mem)
	lv.Copy(r)
	r.frob(f, 8, mem)
	r.Mul(lv, mem)

	/* Hard part of final exp */
	// See https://eprint.iacr.org/2020/875.pdf
	y1 := NewFP48copy(r, mem)
	y1.uSqr(mem)
	y1.Mul(r, mem) // y1=r^3

	y0 := NewFP48copy(r.Pow(x, mem), mem)
	y0.conj(mem)
	t0 := NewFP48copy(r, mem)
	t0.conj(mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	y0.Copy(r.Pow(x, mem))
	y0.conj(mem)
	t0.Copy(r)
	t0.conj(mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	// ^(x+p)
	y0.Copy(r.Pow(x, mem))
	y0.conj(mem)
	t0.Copy(r)
	t0.frob(f, 1, mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	// ^(x^2+p^2)
	y0.Copy(r.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	t0.Copy(r)
	t0.frob(f, 2, mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	// ^(x^4+p^4)
	y0.Copy(r.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	t0.Copy(r)
	t0.frob(f, 4, mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	// ^(x^8+p^8-1)
	y0.Copy(r.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	y0.Copy(y0.Pow(x, mem))
	t0.Copy(r)
	t0.frob(f, 8, mem)
	y0.Mul(t0, mem)
	t0.Copy(r)
	t0.conj(mem)
	r.Copy(y0)
	r.Mul(t0, mem)

	r.Mul(y1, mem)
	r.reduce(mem)
	mem.Free()

	return r
}

/* GLV method */
func glv(ee *BIG, mem *arena.Arena) []*BIG {
	var u []*BIG

	q := NewBIGints(CURVE_Order, mem)
	x := NewBIGints(CURVE_Bnx, mem)
	x2 := smul(x, x)
	x = smul(x2, x2)
	x2 = smul(x, x)
	bd := uint(q.nbits() - x2.nbits())
	u = append(u, NewBIGcopy(ee, mem))
	u[0].ctmod(x2, bd, mem)
	u = append(u, NewBIGcopy(ee, mem))
	u[1].ctdiv(x2, bd, mem)
	u[1].rsub(q)
	return u
}

/* Galbraith & Scott Method */
func gs(ee *BIG, mem *arena.Arena) []*BIG {
	var u []*BIG

	q := NewBIGints(CURVE_Order, mem)
	x := NewBIGints(CURVE_Bnx, mem)
	bd := uint(q.nbits() - x.nbits())
	w := NewBIGcopy(ee, mem)
	for i := 0; i < 15; i++ {
		u = append(u, NewBIGcopy(w, mem))
		u[i].ctmod(x, bd, mem)
		w.ctdiv(x, bd, mem)
	}
	u = append(u, NewBIGcopy(w, mem))
	u[1].copy(Modneg(u[1], q, mem))
	u[3].copy(Modneg(u[3], q, mem))
	u[5].copy(Modneg(u[5], q, mem))
	u[7].copy(Modneg(u[7], q, mem))
	u[9].copy(Modneg(u[9], q, mem))
	u[11].copy(Modneg(u[11], q, mem))
	u[13].copy(Modneg(u[13], q, mem))
	u[15].copy(Modneg(u[15], q, mem))

	return u
}

/* Multiply P by e in group G1 */
func G1mul(P *ECP, e *BIG, mem *arena.Arena) *ECP {
	var R *ECP
	q := NewBIGints(CURVE_Order, mem)
	ee := NewBIGcopy(e, mem)
	ee.Mod(q, mem)
	R = NewECP(mem)
	R.Copy(P)
	Q := NewECP(mem)
	Q.Copy(P)
	Q.Affine(mem)

	cru := NewFPbig(NewBIGints(CRu, mem), mem)
	t := NewBIGint(0, mem)
	u := glv(ee, mem)
	Q.getx().Mul(cru, mem)

	np := u[0].nbits()
	t.copy(Modneg(u[0], q, mem))
	nn := t.nbits()
	if nn < np {
		u[0].copy(t)
		R.Neg(mem)
	}

	np = u[1].nbits()
	t.copy(Modneg(u[1], q, mem))
	nn = t.nbits()
	if nn < np {
		u[1].copy(t)
		Q.Neg(mem)
	}
	u[0].norm()
	u[1].norm()
	R = R.Mul2(u[0], Q, u[1], mem)

	return R
}

/* Multiply P by e in group G2 */
func G2mul(P *ECP8, e *BIG, mem *arena.Arena) *ECP8 {
	var R *ECP8
	q := NewBIGints(CURVE_Order, mem)
	ee := NewBIGcopy(e, mem)
	ee.Mod(q, mem)
	var Q []*ECP8

	F := ECP8_frob_constants()
	u := gs(ee, mem)

	t := NewBIGint(0, mem)

	Q = append(Q, NewECP8(mem))
	Q[0].Copy(P)
	for i := 1; i < 16; i++ {
		Q = append(Q, NewECP8(mem))
		Q[i].Copy(Q[i-1])
		Q[i].frob(F, 1)
	}
	for i := 0; i < 16; i++ {
		np := u[i].nbits()
		t.copy(Modneg(u[i], q, mem))
		nn := t.nbits()
		if nn < np {
			u[i].copy(t)
			Q[i].Neg(mem)
		}
		u[i].norm()
	}

	R = Mul16(Q, u, mem)
	return R
}

/* f=f^e */
/* Note that this method requires a lot of RAM!  */
// func GTpow(d *FP48, e *BIG) *FP48 {
// 	var r *FP48
// 	q := NewBIGints(CURVE_Order)
// 	ee := NewBIGcopy(e)
// 	ee.Mod(q)
// 	if USE_GS_GT {
// 		var g []*FP48
// 		f := NewFP2bigs(NewBIGints(Fra), NewBIGints(Frb))
// 		t := NewBIGint(0)

// 		u := gs(ee)

// 		g = append(g, NewFP48copy(d))
// 		for i := 1; i < 16; i++ {
// 			g = append(g, NewFP48())
// 			g[i].Copy(g[i-1])
// 			g[i].frob(f, 1)
// 		}
// 		for i := 0; i < 16; i++ {
// 			np := u[i].nbits()
// 			t.copy(Modneg(u[i], q))
// 			nn := t.nbits()
// 			if nn < np {
// 				u[i].copy(t)
// 				g[i].conj()
// 			}
// 			u[i].norm()
// 		}
// 		r = pow16(g, u)
// 	} else {
// 		r = d.Pow(ee)
// 	}
// 	return r
// }

/* test G1 group membership */
func G1member(P *ECP, mem *arena.Arena) bool {
	if P.Is_infinity(mem) {
		return false
	}
	x := NewBIGints(CURVE_Bnx, mem)
	cru := NewFPbig(NewBIGints(CRu, mem), mem)
	W := NewECP(mem)
	W.Copy(P)
	W.getx().Mul(cru, mem)
	T := P.lmul(x, mem, mem)
	if P.Equals(T) {
		return false
	} // P is of low order
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T = T.Mul(x, mem, mem)
	T.Neg(mem)
	if !W.Equals(T) {
		return false
	}

	// Not needed
	//	W.Add(P);
	//	T.getx().Mul(cru)
	//	W.Add(T)
	//	if !W.Is_infinity() {return false}
	/*
		q := NewBIGints(CURVE_Order)
		if P.Is_infinity() {return false}
		W:=P.Mul(q)
		if !W.Is_infinity() {return false} */
	return true
}

/* test G2 group membership */
func G2member(P *ECP8, mem *arena.Arena) bool {
	if P.Is_infinity(mem) {
		return false
	}
	F := ECP8_frob_constants()
	x := NewBIGints(CURVE_Bnx, mem)
	W := NewECP8(mem)
	W.Copy(P)
	W.frob(F, 1)
	T := P.Mul(x, mem)
	T.Neg(mem)
	/*
	   	R:=NewECP8(); R.Copy(W)
	       R.frob(F,1)
	       W.Sub(R)
	       R.Copy(T)
	       R.frob(F,1)
	       W.Add(R)
	*/
	if !W.Equals(T) {
		return false
	}
	return true
	/*
		q := NewBIGints(CURVE_Order)
		if P.Is_infinity() {return false}
		W:=P.Mul(q)
		if !W.Is_infinity() {return false}
		return true */
}

/* Check that m is in cyclotomic sub-group */
/* Check that m!=1, conj(m)*m==1, and m.m^{p^16}=m^{p^8} */
func GTcyclotomic(m *FP48) bool {
	if m.Isunity() {
		return false
	}
	r := NewFP48copy(m, nil)
	r.conj(nil)
	r.Mul(m, nil)
	if !r.Isunity() {
		return false
	}

	f := NewFP2bigs(NewBIGints(Fra, nil), NewBIGints(Frb, nil), nil)

	r.Copy(m)
	r.frob(f, 8, nil)
	w := NewFP48copy(r, nil)
	w.frob(f, 8, nil)
	w.Mul(m, nil)
	if !w.Equals(r) {
		return false
	}
	return true
}

/* test for full GT membership */
func GTmember(m *FP48) bool {
	if !GTcyclotomic(m) {
		return false
	}
	f := NewFP2bigs(NewBIGints(Fra, nil), NewBIGints(Frb, nil), nil)
	x := NewBIGints(CURVE_Bnx, nil)

	r := NewFP48copy(m, nil)
	r.frob(f, 1, nil)
	t := m.Pow(x, nil)

	t.conj(nil)
	if !r.Equals(t) {
		return false
	}
	return true

	/*
		q := NewBIGints(CURVE_Order)
		r := m.Pow(q)
		if !r.Isunity() {
			return false
		}
		return true */
}
