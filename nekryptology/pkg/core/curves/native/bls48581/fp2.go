/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/ext..
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

/* Finite Field arithmetic  Fp^2 functions */

/* FP2 elements are of the form a+ib, where i is sqrt(-1) */

package bls48581

import (
	"arena"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581/ext"
)

//import "fmt"

type FP2 struct {
	a *FP
	b *FP
}

func NewFP2(mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFP(mem)
		F.b = NewFP(mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFP(nil)
		F.b = NewFP(nil)
		return F
	}
}

/* Constructors */
func NewFP2int(a int, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPint(a, mem)
		F.b = NewFP(mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPint(a, nil)
		F.b = NewFP(nil)
		return F
	}
}

func NewFP2ints(a int, b int, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPint(a, mem)
		F.b = NewFPint(b, mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPint(a, nil)
		F.b = NewFPint(b, nil)
		return F
	}
}

func NewFP2copy(x *FP2, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPcopy(x.a, mem)
		F.b = NewFPcopy(x.b, mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPcopy(x.a, nil)
		F.b = NewFPcopy(x.b, nil)
		return F
	}
}

func NewFP2fps(c *FP, d *FP, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPcopy(c, mem)
		F.b = NewFPcopy(d, mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPcopy(c, nil)
		F.b = NewFPcopy(d, nil)
		return F
	}
}

func NewFP2bigs(c *BIG, d *BIG, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPbig(c, mem)
		F.b = NewFPbig(d, mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPbig(c, nil)
		F.b = NewFPbig(d, nil)
		return F
	}
}

func NewFP2fp(c *FP, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPcopy(c, mem)
		F.b = NewFP(mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPcopy(c, nil)
		F.b = NewFP(nil)
		return F
	}
}

func NewFP2big(c *BIG, mem *arena.Arena) *FP2 {
	if mem != nil {
		F := arena.New[FP2](mem)
		F.a = NewFPbig(c, mem)
		F.b = NewFP(mem)
		return F
	} else {
		F := new(FP2)
		F.a = NewFPbig(c, nil)
		F.b = NewFP(nil)
		return F
	}
}

func NewFP2rand(rng *ext.RAND) *FP2 {
	F := NewFP2fps(NewFPrand(rng), NewFPrand(rng), nil)
	return F
}

/* reduce components mod Modulus */
func (F *FP2) reduce(mem *arena.Arena) {
	F.a.reduce(mem)
	F.b.reduce(mem)
}

/* normalise components of w */
func (F *FP2) norm() {
	F.a.norm()
	F.b.norm()
}

/* test this=0 ? */
func (F *FP2) IsZero(mem *arena.Arena) bool {
	return (F.a.IsZero(mem) && F.b.IsZero(mem))
}

func (F *FP2) islarger() int {
	if F.IsZero(nil) {
		return 0
	}
	cmp := F.b.islarger()
	if cmp != 0 {
		return cmp
	}
	return F.a.islarger()
}

func (F *FP2) ToBytes(bf []byte) {
	var t [int(MODBYTES)]byte
	MB := int(MODBYTES)
	F.b.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i] = t[i]
	}
	F.a.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i+MB] = t[i]
	}
}

func FP2_fromBytes(bf []byte) *FP2 {
	var t [int(MODBYTES)]byte
	MB := int(MODBYTES)
	for i := 0; i < MB; i++ {
		t[i] = bf[i]
	}
	tb := FP_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = bf[i+MB]
	}
	ta := FP_fromBytes(t[:])
	return NewFP2fps(ta, tb, nil)
}

func (F *FP2) cmove(g *FP2, d int) {
	F.a.cmove(g.a, d)
	F.b.cmove(g.b, d)
}

/* test this=1 ? */
func (F *FP2) isunity() bool {
	mem := arena.NewArena()
	defer mem.Free()
	one := NewFPint(1, mem)
	return (F.a.Equals(one) && F.b.IsZero(mem))
}

/* test this=x */
func (F *FP2) Equals(x *FP2) bool {
	return (F.a.Equals(x.a) && F.b.Equals(x.b))
}

/* extract a */
func (F *FP2) GetA(mem *arena.Arena) *BIG {
	return F.a.Redc(mem)
}

/* extract b */
func (F *FP2) GetB(mem *arena.Arena) *BIG {
	return F.b.Redc(mem)
}

/* copy this=x */
func (F *FP2) copy(x *FP2) {
	F.a.copy(x.a)
	F.b.copy(x.b)
}

/* set this=0 */
func (F *FP2) zero() {
	F.a.zero()
	F.b.zero()
}

/* set this=1 */
func (F *FP2) one() {
	F.a.one()
	F.b.zero()
}

/* Return sign */
func (F *FP2) sign(mem *arena.Arena) int {
	p1 := F.a.sign(mem)
	p2 := F.b.sign(mem)
	var u int
	if BIG_ENDIAN_SIGN {
		if F.b.IsZero(mem) {
			u = 1
		} else {
			u = 0
		}
		p2 ^= (p1 ^ p2) & u
		return p2
	} else {
		if F.a.IsZero(mem) {
			u = 1
		} else {
			u = 0
		}
		p1 ^= (p1 ^ p2) & u
		return p1
	}
}

/* negate this mod Modulus */
func (F *FP2) Neg(mem *arena.Arena) {
	m := NewFPcopy(F.a, mem)
	t := NewFP(mem)

	m.Add(F.b, mem)
	m.Neg(mem)
	t.copy(m)
	t.Add(F.b, mem)
	F.b.copy(m)
	F.b.Add(F.a, mem)
	F.a.copy(t)
}

/* set to a-ib */
func (F *FP2) conj(mem *arena.Arena) {
	F.b.Neg(mem)
	F.b.norm()
}

/* this+=a */
func (F *FP2) Add(x *FP2, mem *arena.Arena) {
	F.a.Add(x.a, mem)
	F.b.Add(x.b, mem)
}

/* this-=a */
func (F *FP2) Sub(x *FP2, mem *arena.Arena) {
	m := NewFP2copy(x, mem)
	m.Neg(mem)
	F.Add(m, mem)
}

/* this-=a */
func (F *FP2) rsub(x *FP2, mem *arena.Arena) {
	F.Neg(mem)
	F.Add(x, mem)
}

/* this*=s, where s is an FP */
func (F *FP2) pmul(s *FP, mem *arena.Arena) {
	F.a.Mul(s, mem)
	F.b.Mul(s, mem)
}

/* this*=i, where i is an int */
func (F *FP2) imul(c int, mem *arena.Arena) {
	F.a.imul(c, mem)
	F.b.imul(c, mem)
}

/* this*=this */
func (F *FP2) Sqr(mem *arena.Arena) {
	w1 := NewFPcopy(F.a, mem)
	w3 := NewFPcopy(F.a, mem)
	mb := NewFPcopy(F.b, mem)
	w1.Add(F.b, mem)

	w3.Add(F.a, mem)
	w3.norm()
	F.b.Mul(w3, mem)

	mb.Neg(mem)
	F.a.Add(mb, mem)

	w1.norm()
	F.a.norm()

	F.a.Mul(w1, mem)
}

/* this*=y */
/* Now using Lazy reduction */
func (F *FP2) Mul(y *FP2, mem *arena.Arena) {

	if int64(F.a.XES+F.b.XES)*int64(y.a.XES+y.b.XES) > int64(FEXCESS) {
		if F.a.XES > 1 {
			F.a.reduce(mem)
		}
		if F.b.XES > 1 {
			F.b.reduce(mem)
		}
	}

	pR := NewDBIG(mem)
	C := NewBIGcopy(F.a.x, mem)
	D := NewBIGcopy(y.a.x, mem)
	p := NewBIGints(Modulus, mem)

	pR.ucopy(p)

	A := mul(F.a.x, y.a.x, mem)
	B := mul(F.b.x, y.b.x, mem)

	C.Add(F.b.x)
	C.norm()
	D.Add(y.b.x)
	D.norm()

	E := mul(C, D, mem)
	FF := NewDBIGcopy(A, mem)
	FF.Add(B)
	B.rsub(pR)

	A.Add(B)
	A.norm()
	E.Sub(FF)
	E.norm()

	F.a.x.copy(mod(A, mem))
	F.a.XES = 3
	F.b.x.copy(mod(E, mem))
	F.b.XES = 2

}

/*
	func (F *FP2) pow(b *BIG)  {
		w := NewFP2copy(F);
		r := NewFP2int(1)
		z := NewBIGcopy(b)
		for true {
			bt := z.parity()
			z.shr(1)
			if bt==1 {
				r.Mul(w)
			}
			if z.IsZero() {break}
			w.Sqr()
		}
		r.reduce()
		F.copy(r)
	}
*/
func (F *FP2) qr(h *FP) int {
	mem := arena.NewArena()
	defer mem.Free()
	c := NewFP2copy(F, mem)
	c.conj(mem)
	c.Mul(F, mem)
	return c.a.qr(h)
}

/* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
func (F *FP2) Sqrt(h *FP, mem *arena.Arena) {
	if F.IsZero(mem) {
		return
	}
	w1 := NewFPcopy(F.b, mem)
	w2 := NewFPcopy(F.a, mem)
	w3 := NewFP(mem)
	w4 := NewFP(mem)
	hint := NewFP(mem)
	w1.Sqr(mem)
	w2.Sqr(mem)
	w1.Add(w2, mem)
	w1.norm()

	w1 = w1.Sqrt(h, mem)
	w2.copy(F.a)
	w3.copy(F.a)

	w2.Add(w1, mem)
	w2.norm()
	w2.div2(mem)

	w1.copy(F.b)
	w1.div2(mem)
	qr := w2.qr(hint)

	// tweak hint
	w3.copy(hint)
	w3.Neg(mem)
	w3.norm()
	w4.copy(w2)
	w4.Neg(mem)
	w4.norm()

	w2.cmove(w4, 1-qr)
	hint.cmove(w3, 1-qr)

	F.a.copy(w2.Sqrt(hint, mem))
	w3.copy(w2)
	w3.Invert(hint, mem)
	w3.Mul(F.a, mem)
	F.b.copy(w3)
	F.b.Mul(w1, mem)
	w4.copy(F.a)

	F.a.cmove(F.b, 1-qr)
	F.b.cmove(w4, 1-qr)

	/*
		F.a.copy(w2.sqrt(hint))
		w3.copy(w2); w3.Invert(hint)
		w3.Mul(F.a)
		F.b.copy(w3); F.b.Mul(w1)

		hint.Neg(); hint.norm()
		w2.Neg(); w2.norm()

		w4.copy(w2.sqrt(hint))
		w3.copy(w2); w3.Invert(hint)
		w3.Mul(w4)
		w3.Mul(w1)

		F.a.cmove(w3,1-qr)
		F.b.cmove(w4,1-qr)
	*/

	sgn := F.sign(mem)
	nr := NewFP2copy(F, mem)
	nr.Neg(mem)
	nr.norm()
	F.cmove(nr, sgn)
}

/* output to hex string */
func (F *FP2) ToString() string {
	return ("[" + F.a.ToString() + "," + F.b.ToString() + "]")
}

/* output to hex string */
func (F *FP2) toString() string {
	return ("[" + F.a.ToString() + "," + F.b.ToString() + "]")
}

/* this=1/this */
func (F *FP2) Invert(h *FP, mem *arena.Arena) {
	F.norm()
	w1 := NewFPcopy(F.a, mem)
	w2 := NewFPcopy(F.b, mem)

	w1.Sqr(mem)
	w2.Sqr(mem)
	w1.Add(w2, mem)
	w1.Invert(h, mem)
	F.a.Mul(w1, mem)
	w1.Neg(mem)
	w1.norm()
	F.b.Mul(w1, mem)
}

/* this/=2 */
func (F *FP2) div2(mem *arena.Arena) {
	F.a.div2(mem)
	F.b.div2(mem)
}

/* this*=sqrt(-1) */
func (F *FP2) times_i(mem *arena.Arena) {
	z := NewFPcopy(F.a, mem)
	F.a.copy(F.b)
	F.a.Neg(mem)
	F.b.copy(z)
}

/* w*=(1+sqrt(-1)) */
/* where X*2-(2^i+sqrt(-1)) is irreducible for FP4 */
func (F *FP2) Mul_ip(mem *arena.Arena) {
	t := NewFP2copy(F, mem)
	i := QNRI
	F.times_i(mem)
	for i > 0 {
		t.Add(t, mem)
		t.norm()
		i--
	}
	F.Add(t, mem)

	if TOWER == POSITOWER {
		F.norm()
		F.Neg(mem)
	}

}

/* w/=(2^i+sqrt(-1)) */
func (F *FP2) div_ip(mem *arena.Arena) {
	z := NewFP2ints(1<<uint(QNRI), 1, nil)
	z.Invert(nil, mem)
	F.norm()
	F.Mul(z, mem)
	if TOWER == POSITOWER {
		F.Neg(mem)
		F.norm()
	}
}
