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

/* MiotCL Fp^12 functions */
/* FP12 elements are of the form a+i.b+i^2.c */

package bls48581

import "arena"

//import "fmt"

type FP48 struct {
	a     *FP16
	b     *FP16
	c     *FP16
	stype int
}

/* Constructors */
func NewFP48fp16(d *FP16, mem *arena.Arena) *FP48 {
	if mem != nil {
		F := arena.New[FP48](mem)
		F.a = NewFP16copy(d, mem)
		F.b = NewFP16(mem)
		F.c = NewFP16(mem)
		F.stype = FP_SPARSEST
		return F
	} else {
		F := new(FP48)
		F.a = NewFP16copy(d, nil)
		F.b = NewFP16(nil)
		F.c = NewFP16(nil)
		F.stype = FP_SPARSEST
		return F
	}
}

func NewFP48(mem *arena.Arena) *FP48 {
	if mem != nil {
		F := arena.New[FP48](mem)
		F.a = NewFP16(mem)
		F.b = NewFP16(mem)
		F.c = NewFP16(mem)
		F.stype = FP_ZERO
		return F
	} else {
		F := new(FP48)
		F.a = NewFP16(nil)
		F.b = NewFP16(nil)
		F.c = NewFP16(nil)
		F.stype = FP_ZERO
		return F
	}
}

func NewFP48int(d int, mem *arena.Arena) *FP48 {
	var F *FP48
	if mem != nil {
		F = arena.New[FP48](mem)
	} else {
		F = new(FP48)
	}
	F.a = NewFP16int(d, mem)
	F.b = NewFP16(mem)
	F.c = NewFP16(mem)
	if d == 1 {
		F.stype = FP_ONE
	} else {
		F.stype = FP_SPARSEST
	}
	return F
}

func NewFP48fp16s(d *FP16, e *FP16, f *FP16, mem *arena.Arena) *FP48 {
	var F *FP48
	if mem != nil {
		F = arena.New[FP48](mem)
	} else {
		F = new(FP48)
	}
	F.a = d
	F.b = e
	F.c = f
	F.stype = FP_DENSE
	return F
}

func NewFP48copy(x *FP48, mem *arena.Arena) *FP48 {
	var F *FP48
	if mem != nil {
		F = arena.New[FP48](mem)
	} else {
		F = new(FP48)
	}
	F.a = NewFP16copy(x.a, mem)
	F.b = NewFP16copy(x.b, mem)
	F.c = NewFP16copy(x.c, mem)
	F.stype = x.stype
	return F
}

/* reduce all components of this mod Modulus */
func (F *FP48) reduce(mem *arena.Arena) {
	F.a.reduce(mem)
	F.b.reduce(mem)
	F.c.reduce(mem)
}

/* normalise all components of this */
func (F *FP48) norm() {
	F.a.norm()
	F.b.norm()
	F.c.norm()
}

/* test x==0 ? */
func (F *FP48) IsZero(mem *arena.Arena) bool {
	return (F.a.IsZero(mem) && F.b.IsZero(mem) && F.c.IsZero(mem))
}

/* Conditional move */
func (F *FP48) cmove(g *FP48, d int) {
	F.a.cmove(g.a, d)
	F.b.cmove(g.b, d)
	F.c.cmove(g.c, d)
	d = ^(d - 1)
	F.stype ^= (F.stype ^ g.stype) & d
}

/* Constant time select from pre-computed table */
func (F *FP48) selector(g []*FP48, b int32) {

	m := b >> 31
	babs := (b ^ m) - m

	babs = (babs - 1) / 2

	F.cmove(g[0], teq(babs, 0)) // conditional move
	F.cmove(g[1], teq(babs, 1))
	F.cmove(g[2], teq(babs, 2))
	F.cmove(g[3], teq(babs, 3))
	F.cmove(g[4], teq(babs, 4))
	F.cmove(g[5], teq(babs, 5))
	F.cmove(g[6], teq(babs, 6))
	F.cmove(g[7], teq(babs, 7))

	invF := NewFP48copy(F, nil)
	invF.conj(nil)
	F.cmove(invF, int(m&1))
}

/* test x==1 ? */
func (F *FP48) Isunity() bool {
	mem := arena.NewArena()
	defer mem.Free()
	one := NewFP16int(1, mem)
	return (F.a.Equals(one) && F.b.IsZero(mem) && F.c.IsZero(mem))
}

/* return 1 if x==y, else 0 */
func (F *FP48) Equals(x *FP48) bool {
	return (F.a.Equals(x.a) && F.b.Equals(x.b) && F.c.Equals(x.c))
}

/* extract a from this */
func (F *FP48) geta() *FP16 {
	return F.a
}

/* extract b */
func (F *FP48) getb() *FP16 {
	return F.b
}

/* extract c */
func (F *FP48) getc() *FP16 {
	return F.c
}

/* copy this=x */
func (F *FP48) Copy(x *FP48) {
	F.a.copy(x.a)
	F.b.copy(x.b)
	F.c.copy(x.c)
	F.stype = x.stype
}

/* set this=1 */
func (F *FP48) one() {
	F.stype = FP_ONE
	F.a.one()
	F.b.zero()
	F.c.zero()
}

/* set this=0 */
func (F *FP48) zero() {
	F.a.zero()
	F.b.zero()
	F.c.zero()
	F.stype = FP_ZERO
}

/* this=conj(this) */
func (F *FP48) conj(mem *arena.Arena) {
	F.a.conj(mem)
	F.b.nconj(mem)
	F.c.conj(mem)
}

/* Granger-Scott Unitary Squaring */
func (F *FP48) uSqr(mem *arena.Arena) {
	A := NewFP16copy(F.a, mem)
	B := NewFP16copy(F.c, mem)
	C := NewFP16copy(F.b, mem)
	D := NewFP16(mem)

	F.a.Sqr(mem)
	D.copy(F.a)
	D.Add(F.a, mem)
	F.a.Add(D, mem)

	F.a.norm()
	A.nconj(mem)

	A.Add(A, mem)
	F.a.Add(A, mem)
	B.Sqr(mem)
	B.times_i(mem)

	D.copy(B)
	D.Add(B, mem)
	B.Add(D, mem)
	B.norm()

	C.Sqr(mem)
	D.copy(C)
	D.Add(C, mem)
	C.Add(D, mem)
	C.norm()

	F.b.conj(mem)
	F.b.Add(F.b, mem)
	F.c.nconj(mem)

	F.c.Add(F.c, mem)
	F.b.Add(B, mem)
	F.c.Add(C, mem)
	F.reduce(mem)
	F.stype = FP_DENSE
}

/* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
func (F *FP48) Sqr(mem *arena.Arena) {
	if F.stype == FP_ONE {
		return
	}
	A := NewFP16copy(F.a, mem)
	B := NewFP16copy(F.b, mem)
	C := NewFP16copy(F.c, mem)
	D := NewFP16copy(F.a, mem)

	A.Sqr(mem)
	B.Mul(F.c, mem)
	B.Add(B, mem)
	B.norm()
	C.Sqr(mem)
	D.Mul(F.b, mem)
	D.Add(D, mem)

	F.c.Add(F.a, mem)
	F.c.Add(F.b, mem)
	F.c.norm()
	F.c.Sqr(mem)

	F.a.copy(A)

	A.Add(B, mem)
	A.norm()
	A.Add(C, mem)
	A.Add(D, mem)
	A.norm()

	A.Neg(mem)
	B.times_i(mem)
	C.times_i(mem)

	F.a.Add(B, mem)

	F.b.copy(C)
	F.b.Add(D, mem)
	F.c.Add(A, mem)
	if F.stype == FP_SPARSER || F.stype == FP_SPARSEST {
		F.stype = FP_SPARSE
	} else {
		F.stype = FP_DENSE
	}
	F.norm()
}

/* FP48 full multiplication this=this*y */
func (F *FP48) Mul(y *FP48, mem *arena.Arena) {
	z0 := NewFP16copy(F.a, mem)
	z1 := NewFP16(mem)
	z2 := NewFP16copy(F.b, mem)
	z3 := NewFP16(mem)
	t0 := NewFP16copy(F.a, mem)
	t1 := NewFP16copy(y.a, mem)

	z0.Mul(y.a, mem)
	z2.Mul(y.b, mem)

	t0.Add(F.b, mem)
	t0.norm()
	t1.Add(y.b, mem)
	t1.norm()

	z1.copy(t0)
	z1.Mul(t1, mem)
	t0.copy(F.b)
	t0.Add(F.c, mem)
	t0.norm()

	t1.copy(y.b)
	t1.Add(y.c, mem)
	t1.norm()
	z3.copy(t0)
	z3.Mul(t1, mem)

	t0.copy(z0)
	t0.Neg(mem)
	t1.copy(z2)
	t1.Neg(mem)

	z1.Add(t0, mem)
	//z1.norm();
	F.b.copy(z1)
	F.b.Add(t1, mem)

	z3.Add(t1, mem)
	z2.Add(t0, mem)

	t0.copy(F.a)
	t0.Add(F.c, mem)
	t0.norm()
	t1.copy(y.a)
	t1.Add(y.c, mem)
	t1.norm()
	t0.Mul(t1, mem)
	z2.Add(t0, mem)

	t0.copy(F.c)
	t0.Mul(y.c, mem)
	t1.copy(t0)
	t1.Neg(mem)

	F.c.copy(z2)
	F.c.Add(t1, mem)
	z3.Add(t1, mem)
	t0.times_i(mem)
	F.b.Add(t0, mem)
	z3.norm()
	z3.times_i(mem)
	F.a.copy(z0)
	F.a.Add(z3, mem)
	F.stype = FP_DENSE
	F.norm()
}

/* FP48 full multiplication w=w*y */
/* Supports sparse multiplicands */
/* Usually w is denser than y */
func (F *FP48) ssmul(y *FP48, mem *arena.Arena) {
	if F.stype == FP_ONE {
		F.Copy(y)
		return
	}
	if y.stype == FP_ONE {
		return
	}
	if y.stype >= FP_SPARSE {
		z0 := NewFP16copy(F.a, mem)
		z1 := NewFP16(mem)
		z2 := NewFP16(mem)
		z3 := NewFP16(mem)
		z0.Mul(y.a, mem)

		z2.copy(F.b)
		z2.Mul(y.b, mem)
		t0 := NewFP16copy(F.a, mem)
		t1 := NewFP16copy(y.a, mem)
		t0.Add(F.b, mem)
		t0.norm()
		t1.Add(y.b, mem)
		t1.norm()

		z1.copy(t0)
		z1.Mul(t1, mem)
		t0.copy(F.b)
		t0.Add(F.c, mem)
		t0.norm()
		t1.copy(y.b)
		t1.Add(y.c, mem)
		t1.norm()

		z3.copy(t0)
		z3.Mul(t1, mem)

		t0.copy(z0)
		t0.Neg(mem)
		t1.copy(z2)
		t1.Neg(mem)

		z1.Add(t0, mem)
		F.b.copy(z1)
		F.b.Add(t1, mem)

		z3.Add(t1, mem)
		z2.Add(t0, mem)

		t0.copy(F.a)
		t0.Add(F.c, mem)
		t0.norm()
		t1.copy(y.a)
		t1.Add(y.c, mem)
		t1.norm()

		t0.Mul(t1, mem)
		z2.Add(t0, mem)

		if y.stype == FP_SPARSE || F.stype == FP_SPARSE {
			t0.geta().copy(F.c.geta())
			t0.geta().Mul(y.c.geta(), mem)
			t0.getb().zero()
			if y.stype != FP_SPARSE {
				t0.getb().copy(F.c.geta())
				t0.getb().Mul(y.c.getb(), mem)
			}
			if F.stype != FP_SPARSE {
				t0.getb().copy(F.c.getb())
				t0.getb().Mul(y.c.geta(), mem)
			}
		} else {
			t0.copy(F.c)
			t0.Mul(y.c, mem)
		}
		t1.copy(t0)
		t1.Neg(mem)

		F.c.copy(z2)
		F.c.Add(t1, mem)
		z3.Add(t1, mem)
		t0.times_i(mem)
		F.b.Add(t0, mem)
		z3.norm()
		z3.times_i(mem)
		F.a.copy(z0)
		F.a.Add(z3, mem)
	} else {
		if F.stype == FP_SPARSER || F.stype == FP_SPARSEST {
			F.smul(y, mem)
			return
		}
		z0 := NewFP16copy(F.a, mem)
		z2 := NewFP16copy(F.b, mem)
		z3 := NewFP16copy(F.b, mem)
		t0 := NewFP16(mem)
		t1 := NewFP16copy(y.a, mem)
		z0.Mul(y.a, mem)

		if y.stype == FP_SPARSEST {
			z2.tmul(y.b.a.a.a.a, mem)
		} else {
			z2.pmul(y.b.geta(), mem)
		}
		F.b.Add(F.a, mem)
		t1.geta().Add(y.b.geta(), mem)

		t1.norm()
		F.b.norm()
		F.b.Mul(t1, mem)
		z3.Add(F.c, mem)
		z3.norm()

		if y.stype == FP_SPARSEST {
			z3.tmul(y.b.a.a.a.a, mem)
		} else {
			z3.pmul(y.b.geta(), mem)
		}

		t0.copy(z0)
		t0.Neg(mem)
		t1.copy(z2)
		t1.Neg(mem)

		F.b.Add(t0, mem)

		F.b.Add(t1, mem)
		z3.Add(t1, mem)
		z2.Add(t0, mem)

		t0.copy(F.a)
		t0.Add(F.c, mem)
		t0.norm()
		z3.norm()
		t0.Mul(y.a, mem)
		F.c.copy(z2)
		F.c.Add(t0, mem)

		z3.times_i(mem)
		F.a.copy(z0)
		F.a.Add(z3, mem)
	}
	F.stype = FP_DENSE
	F.norm()
}

/* Special case of multiplication arises from special form of ATE pairing line function */
func (F *FP48) smul(y *FP48, mem *arena.Arena) {
	w1 := NewFP8copy(F.a.geta(), mem)
	w2 := NewFP8copy(F.a.getb(), mem)
	var w3 *FP8

	w1.Mul(y.a.geta(), mem)
	w2.Mul(y.a.getb(), mem)

	if y.stype == FP_SPARSEST || F.stype == FP_SPARSEST {
		if y.stype == FP_SPARSEST && F.stype == FP_SPARSEST {
			t := NewFPcopy(F.b.a.a.a.a, mem)
			t.Mul(y.b.a.a.a.a, mem)
			w3 = NewFP8fp(t, mem)
		} else {
			if y.stype != FP_SPARSEST {
				w3 = NewFP8copy(y.b.geta(), mem)
				w3.tmul(F.b.a.a.a.a, mem)
			} else {
				w3 = NewFP8copy(F.b.geta(), mem)
				w3.tmul(y.b.a.a.a.a, mem)
			}
		}
	} else {
		w3 = NewFP8copy(F.b.geta(), mem)
		w3.Mul(y.b.geta(), mem)
	}
	ta := NewFP8copy(F.a.geta(), mem)
	tb := NewFP8copy(y.a.geta(), mem)
	ta.Add(F.a.getb(), mem)
	ta.norm()
	tb.Add(y.a.getb(), mem)
	tb.norm()
	tc := NewFP8copy(ta, mem)
	tc.Mul(tb, mem)
	t := NewFP8copy(w1, mem)
	t.Add(w2, mem)
	t.Neg(mem)
	tc.Add(t, mem)

	ta.copy(F.a.geta())
	ta.Add(F.b.geta(), mem)
	ta.norm()
	tb.copy(y.a.geta())
	tb.Add(y.b.geta(), mem)
	tb.norm()
	td := NewFP8copy(ta, mem)
	td.Mul(tb, mem)
	t.copy(w1)
	t.Add(w3, mem)
	t.Neg(mem)
	td.Add(t, mem)

	ta.copy(F.a.getb())
	ta.Add(F.b.geta(), mem)
	ta.norm()
	tb.copy(y.a.getb())
	tb.Add(y.b.geta(), mem)
	tb.norm()
	te := NewFP8copy(ta, mem)
	te.Mul(tb, mem)
	t.copy(w2)
	t.Add(w3, mem)
	t.Neg(mem)
	te.Add(t, mem)

	w2.times_i(mem)
	w1.Add(w2, mem)

	F.a.geta().copy(w1)
	F.a.getb().copy(tc)
	F.b.geta().copy(td)
	F.b.getb().copy(te)
	F.c.geta().copy(w3)
	F.c.getb().zero()

	F.a.norm()
	F.b.norm()
	F.stype = FP_SPARSE
}

/* this=1/this */
func (F *FP48) Invert(mem *arena.Arena) {
	f0 := NewFP16copy(F.a, mem)
	f1 := NewFP16copy(F.b, mem)
	f2 := NewFP16copy(F.a, mem)
	f3 := NewFP16(mem)

	//F.norm()
	f0.Sqr(mem)
	f1.Mul(F.c, mem)
	f1.times_i(mem)
	f0.Sub(f1, mem)
	f0.norm()

	f1.copy(F.c)
	f1.Sqr(mem)
	f1.times_i(mem)
	f2.Mul(F.b, mem)
	f1.Sub(f2, mem)
	f1.norm()

	f2.copy(F.b)
	f2.Sqr(mem)
	f3.copy(F.a)
	f3.Mul(F.c, mem)
	f2.Sub(f3, mem)
	f2.norm()

	f3.copy(F.b)
	f3.Mul(f2, mem)
	f3.times_i(mem)
	F.a.Mul(f0, mem)
	f3.Add(F.a, mem)
	F.c.Mul(f1, mem)
	F.c.times_i(mem)

	f3.Add(F.c, mem)
	f3.norm()
	f3.Invert(mem)

	F.a.copy(f0)
	F.a.Mul(f3, mem)
	F.b.copy(f1)
	F.b.Mul(f3, mem)
	F.c.copy(f2)
	F.c.Mul(f3, mem)
	F.stype = FP_DENSE
}

/* this=this^p using Frobenius */
func (F *FP48) frob(f *FP2, n int, mem *arena.Arena) {
	f2 := NewFP2copy(f, mem)
	f3 := NewFP2copy(f, mem)

	f2.Sqr(mem)
	f3.Mul(f2, mem)

	f3.Mul_ip(mem)
	f3.norm()
	f3.Mul_ip(mem)
	f3.norm()

	for i := 0; i < n; i++ {
		F.a.frob(f3, mem)
		F.b.frob(f3, mem)
		F.c.frob(f3, mem)

		F.b.qmul(f, mem)
		F.b.times_i4(mem)
		F.b.times_i2(mem)
		F.c.qmul(f2, mem)
		F.c.times_i4(mem)
		F.c.times_i4(mem)
		F.c.times_i4(mem)
	}
	F.stype = FP_DENSE
}

/* trace function */
func (F *FP48) trace(mem *arena.Arena) *FP16 {
	t := NewFP16(mem)
	t.copy(F.a)
	t.imul(3, mem)
	t.reduce(mem)
	return t
}

/* convert from byte array to FP48 */
func FP48_fromBytes(w []byte) *FP48 {
	var t [16 * int(MODBYTES)]byte
	MB := 16 * int(MODBYTES)

	for i := 0; i < MB; i++ {
		t[i] = w[i]
	}
	c := FP16_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = w[i+MB]
	}
	b := FP16_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = w[i+2*MB]
	}
	a := FP16_fromBytes(t[:])
	return NewFP48fp16s(a, b, c, nil)
}

/* convert this to byte array */
func (F *FP48) ToBytes(w []byte) {
	var t [16 * int(MODBYTES)]byte
	MB := 16 * int(MODBYTES)
	F.c.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		w[i] = t[i]
	}
	F.b.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		w[i+MB] = t[i]
	}
	F.a.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		w[i+2*MB] = t[i]
	}
}

/* convert to hex string */
func (F *FP48) ToString() string {
	return ("[" + F.a.toString() + "," + F.b.toString() + "," + F.c.toString() + "]")
}

/* this=this^e */
func (F *FP48) Pow(e *BIG, mem *arena.Arena) *FP48 {
	sf := NewFP48copy(F, mem)
	sf.norm()
	e1 := NewBIGcopy(e, mem)
	e1.norm()
	e3 := NewBIGcopy(e1, mem)
	e3.pmul(3)
	e3.norm()

	w := NewFP48copy(sf, mem)
	if e3.IsZero() {
		w.one()
		return w
	}
	nb := e3.nbits()
	for i := nb - 2; i >= 1; i-- {
		w.uSqr(mem)
		bt := e3.bit(i) - e1.bit(i)
		if bt == 1 {
			w.Mul(sf, mem)
		}
		if bt == -1 {
			sf.conj(mem)
			w.Mul(sf, mem)
			sf.conj(mem)
		}
	}
	w.reduce(mem)
	return w

}

/* constant time powering by small integer of max length bts */
func (F *FP48) pinpow(e int, bts int, mem *arena.Arena) {
	var R []*FP48
	R = append(R, NewFP48int(1, mem))
	R = append(R, NewFP48copy(F, mem))

	for i := bts - 1; i >= 0; i-- {
		b := (e >> uint(i)) & 1
		R[1-b].Mul(R[b], mem)
		R[b].uSqr(mem)
	}
	F.Copy(R[0])
}

/* Fast compressed FP16 power of unitary FP48 */
/*
func (F *FP48) Compow(e *BIG, r *BIG) *FP16 {
	q := NewBIGints(Modulus)
	f := NewFP2bigs(NewBIGints(Fra), NewBIGints(Frb))

	m := NewBIGcopy(q)
	m.Mod(r)

	a := NewBIGcopy(e)
	a.Mod(m)

	b := NewBIGcopy(e)
	b.div(m)

	g1 := NewFP48copy(F)
	c := g1.trace()

	if b.IsZero() {
		c = c.xtr_pow(e)
		return c
	}

	g2 := NewFP48copy(F)
	g2.frob(f, 1)
	cp := g2.trace()

	g1.conj()
	g2.Mul(g1)
	cpm1 := g2.trace()
	g2.Mul(g1)
	cpm2 := g2.trace()

	c = c.xtr_pow2(cp, cpm1, cpm2, a, b)
	return c
}
*/
/* p=q0^u0.q1^u1.q2^u2.q3^u3.. */
// Bos & Costello https://eprint.iacr.org/2013/458.pdf
// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
// Side channel attack secure

func pow16(q []*FP48, u []*BIG) *FP48 {
	var g1 []*FP48
	var g2 []*FP48
	var g3 []*FP48
	var g4 []*FP48
	var w1 [NLEN*int(BASEBITS) + 1]int8
	var s1 [NLEN*int(BASEBITS) + 1]int8
	var w2 [NLEN*int(BASEBITS) + 1]int8
	var s2 [NLEN*int(BASEBITS) + 1]int8
	var w3 [NLEN*int(BASEBITS) + 1]int8
	var s3 [NLEN*int(BASEBITS) + 1]int8
	var w4 [NLEN*int(BASEBITS) + 1]int8
	var s4 [NLEN*int(BASEBITS) + 1]int8
	var t []*BIG
	r := NewFP48(nil)
	p := NewFP48(nil)
	mt := NewBIGint(0, nil)
	var bt int8
	var k int

	for i := 0; i < 16; i++ {
		t = append(t, NewBIGcopy(u[i], nil))
	}

	g1 = append(g1, NewFP48copy(q[0], nil)) // q[0]
	g1 = append(g1, NewFP48copy(g1[0], nil))
	g1[1].Mul(q[1], nil) // q[0].q[1]
	g1 = append(g1, NewFP48copy(g1[0], nil))
	g1[2].Mul(q[2], nil) // q[0].q[2]
	g1 = append(g1, NewFP48copy(g1[1], nil))
	g1[3].Mul(q[2], nil) // q[0].q[1].q[2]
	g1 = append(g1, NewFP48copy(g1[0], nil))
	g1[4].Mul(q[3], nil) // q[0].q[3]
	g1 = append(g1, NewFP48copy(g1[1], nil))
	g1[5].Mul(q[3], nil) // q[0].q[1].q[3]
	g1 = append(g1, NewFP48copy(g1[2], nil))
	g1[6].Mul(q[3], nil) // q[0].q[2].q[3]
	g1 = append(g1, NewFP48copy(g1[3], nil))
	g1[7].Mul(q[3], nil) // q[0].q[1].q[2].q[3]

	g2 = append(g2, NewFP48copy(q[4], nil)) // q[0]
	g2 = append(g2, NewFP48copy(g2[0], nil))
	g2[1].Mul(q[5], nil) // q[0].q[1]
	g2 = append(g2, NewFP48copy(g2[0], nil))
	g2[2].Mul(q[6], nil) // q[0].q[2]
	g2 = append(g2, NewFP48copy(g2[1], nil))
	g2[3].Mul(q[6], nil) // q[0].q[1].q[2]
	g2 = append(g2, NewFP48copy(g2[0], nil))
	g2[4].Mul(q[7], nil) // q[0].q[3]
	g2 = append(g2, NewFP48copy(g2[1], nil))
	g2[5].Mul(q[7], nil) // q[0].q[1].q[3]
	g2 = append(g2, NewFP48copy(g2[2], nil))
	g2[6].Mul(q[7], nil) // q[0].q[2].q[3]
	g2 = append(g2, NewFP48copy(g2[3], nil))
	g2[7].Mul(q[7], nil) // q[0].q[1].q[2].q[3]

	g3 = append(g3, NewFP48copy(q[8], nil)) // q[0]
	g3 = append(g3, NewFP48copy(g3[0], nil))
	g3[1].Mul(q[9], nil) // q[0].q[1]
	g3 = append(g3, NewFP48copy(g3[0], nil))
	g3[2].Mul(q[10], nil) // q[0].q[2]
	g3 = append(g3, NewFP48copy(g3[1], nil))
	g3[3].Mul(q[10], nil) // q[0].q[1].q[2]
	g3 = append(g3, NewFP48copy(g3[0], nil))
	g3[4].Mul(q[11], nil) // q[0].q[3]
	g3 = append(g3, NewFP48copy(g3[1], nil))
	g3[5].Mul(q[11], nil) // q[0].q[1].q[3]
	g3 = append(g3, NewFP48copy(g3[2], nil))
	g3[6].Mul(q[11], nil) // q[0].q[2].q[3]
	g3 = append(g3, NewFP48copy(g3[3], nil))
	g3[7].Mul(q[11], nil) // q[0].q[1].q[2].q[3]

	g4 = append(g4, NewFP48copy(q[12], nil)) // q[0]
	g4 = append(g4, NewFP48copy(g4[0], nil))
	g4[1].Mul(q[13], nil) // q[0].q[1]
	g4 = append(g4, NewFP48copy(g4[0], nil))
	g4[2].Mul(q[14], nil) // q[0].q[2]
	g4 = append(g4, NewFP48copy(g4[1], nil))
	g4[3].Mul(q[14], nil) // q[0].q[1].q[2]
	g4 = append(g4, NewFP48copy(g4[0], nil))
	g4[4].Mul(q[15], nil) // q[0].q[3]
	g4 = append(g4, NewFP48copy(g4[1], nil))
	g4[5].Mul(q[15], nil) // q[0].q[1].q[3]
	g4 = append(g4, NewFP48copy(g4[2], nil))
	g4[6].Mul(q[15], nil) // q[0].q[2].q[3]
	g4 = append(g4, NewFP48copy(g4[3], nil))
	g4[7].Mul(q[15], nil) // q[0].q[1].q[2].q[3]

	// Make them odd
	pb1 := 1 - t[0].parity()
	t[0].inc(pb1)
	//	t[0].norm();

	pb2 := 1 - t[4].parity()
	t[4].inc(pb2)
	//	t[4].norm();

	pb3 := 1 - t[8].parity()
	t[8].inc(pb3)
	//	t[8].norm();

	pb4 := 1 - t[12].parity()
	t[12].inc(pb4)
	//	t[12].norm();

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
	p.selector(g1, int32(2*w1[nb-1]+1))
	r.selector(g2, int32(2*w2[nb-1]+1))
	p.Mul(r, nil)
	r.selector(g3, int32(2*w3[nb-1]+1))
	p.Mul(r, nil)
	r.selector(g4, int32(2*w4[nb-1]+1))
	p.Mul(r, nil)
	for i := nb - 2; i >= 0; i-- {
		p.uSqr(nil)
		r.selector(g1, int32(2*w1[i]+s1[i]))
		p.Mul(r, nil)
		r.selector(g2, int32(2*w2[i]+s2[i]))
		p.Mul(r, nil)
		r.selector(g3, int32(2*w3[i]+s3[i]))
		p.Mul(r, nil)
		r.selector(g4, int32(2*w4[i]+s4[i]))
		p.Mul(r, nil)
	}

	// apply correction
	r.Copy(q[0])
	r.conj(nil)
	r.Mul(p, nil)
	p.cmove(r, pb1)
	r.Copy(q[4])
	r.conj(nil)
	r.Mul(p, nil)
	p.cmove(r, pb2)
	r.Copy(q[8])
	r.conj(nil)
	r.Mul(p, nil)
	p.cmove(r, pb3)
	r.Copy(q[12])
	r.conj(nil)
	r.Mul(p, nil)
	p.cmove(r, pb4)

	p.reduce(nil)
	return p
}
