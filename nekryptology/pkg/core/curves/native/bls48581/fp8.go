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

/* Finite Field arithmetic  Fp^8 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1)) */

package bls48581

import (
	"arena"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581/ext"
)

//import "fmt"

type FP8 struct {
	a *FP4
	b *FP4
}

func NewFP8(mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4(mem)
		F.b = NewFP4(mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4(nil)
		F.b = NewFP4(nil)
		return F
	}
}

/* Constructors */
func NewFP8int(a int, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4int(a, mem)
		F.b = NewFP4(mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4int(a, nil)
		F.b = NewFP4(nil)
		return F
	}
}

/* Constructors */
func NewFP8ints(a int, b int, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4int(a, mem)
		F.b = NewFP4int(b, mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4int(a, nil)
		F.b = NewFP4int(b, nil)
		return F
	}
}

func NewFP8copy(x *FP8, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4copy(x.a, mem)
		F.b = NewFP4copy(x.b, mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4copy(x.a, nil)
		F.b = NewFP4copy(x.b, nil)
		return F
	}
}

func NewFP8fp4s(c *FP4, d *FP4, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4copy(c, mem)
		F.b = NewFP4copy(d, mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4copy(c, nil)
		F.b = NewFP4copy(d, nil)
		return F
	}
}

func NewFP8fp4(c *FP4, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4copy(c, mem)
		F.b = NewFP4(mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4copy(c, nil)
		F.b = NewFP4(nil)
		return F
	}
}

func NewFP8fp(c *FP, mem *arena.Arena) *FP8 {
	if mem != nil {
		F := arena.New[FP8](mem)
		F.a = NewFP4fp(c, mem)
		F.b = NewFP4(mem)
		return F
	} else {
		F := new(FP8)
		F.a = NewFP4fp(c, nil)
		F.b = NewFP4(nil)
		return F
	}
}

func NewFP8rand(rng *ext.RAND) *FP8 {
	F := NewFP8fp4s(NewFP4rand(rng), NewFP4rand(rng), nil)
	return F
}

/* reduce all components of this mod Modulus */
func (F *FP8) reduce(mem *arena.Arena) {
	F.a.reduce(mem)
	F.b.reduce(mem)
}

/* normalise all components of this mod Modulus */
func (F *FP8) norm() {
	F.a.norm()
	F.b.norm()
}

/* test this==0 ? */
func (F *FP8) IsZero(mem *arena.Arena) bool {
	return F.a.IsZero(mem) && F.b.IsZero(mem)
}

func (F *FP8) islarger() int {
	if F.IsZero(nil) {
		return 0
	}
	cmp := F.b.islarger()
	if cmp != 0 {
		return cmp
	}
	return F.a.islarger()
}

func (F *FP8) ToBytes(bf []byte) {
	var t [4 * int(MODBYTES)]byte
	MB := 4 * int(MODBYTES)
	F.b.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i] = t[i]
	}
	F.a.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i+MB] = t[i]
	}
}

func FP8_fromBytes(bf []byte) *FP8 {
	var t [4 * int(MODBYTES)]byte
	MB := 4 * int(MODBYTES)
	for i := 0; i < MB; i++ {
		t[i] = bf[i]
	}
	tb := FP4_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = bf[i+MB]
	}
	ta := FP4_fromBytes(t[:])
	return NewFP8fp4s(ta, tb, nil)
}

/* Conditional move */
func (F *FP8) cmove(g *FP8, d int) {
	F.a.cmove(g.a, d)
	F.b.cmove(g.b, d)
}

/* test this==1 ? */
func (F *FP8) isunity() bool {
	mem := arena.NewArena()
	defer mem.Free()
	one := NewFP4int(1, mem)
	return F.a.Equals(one) && F.b.IsZero(mem)
}

/* test is w real? That is in a+ib test b is zero */
func (F *FP8) isreal() bool {
	return F.b.IsZero(nil)
}

/* extract real part a */
func (F *FP8) real() *FP4 {
	return F.a
}

func (F *FP8) geta() *FP4 {
	return F.a
}

/* extract imaginary part b */
func (F *FP8) getb() *FP4 {
	return F.b
}

/* test this=x? */
func (F *FP8) Equals(x *FP8) bool {
	return (F.a.Equals(x.a) && F.b.Equals(x.b))
}

/* copy this=x */
func (F *FP8) copy(x *FP8) {
	F.a.copy(x.a)
	F.b.copy(x.b)
}

/* set this=0 */
func (F *FP8) zero() {
	F.a.zero()
	F.b.zero()
}

/* set this=1 */
func (F *FP8) one() {
	F.a.one()
	F.b.zero()
}

/* Return sign */
func (F *FP8) sign(mem *arena.Arena) int {
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

/* set this=-this */
func (F *FP8) Neg(mem *arena.Arena) {
	F.norm()
	m := NewFP4copy(F.a, mem)
	t := NewFP4(mem)
	m.Add(F.b, mem)
	m.Neg(mem)
	t.copy(m)
	t.Add(F.b, mem)
	F.b.copy(m)
	F.b.Add(F.a, mem)
	F.a.copy(t)
	F.norm()
}

/* this=conjugate(this) */
func (F *FP8) conj(mem *arena.Arena) {
	F.b.Neg(mem)
	F.norm()
}

/* this=-conjugate(this) */
func (F *FP8) nconj(mem *arena.Arena) {
	F.a.Neg(mem)
	F.norm()
}

/* this+=x */
func (F *FP8) Add(x *FP8, mem *arena.Arena) {
	F.a.Add(x.a, mem)
	F.b.Add(x.b, mem)
}

/* this-=x */
func (F *FP8) Sub(x *FP8, mem *arena.Arena) {
	m := NewFP8copy(x, mem)
	m.Neg(mem)
	F.Add(m, mem)
}

/* this-=x */
func (F *FP8) rsub(x *FP8, mem *arena.Arena) {
	F.Neg(mem)
	F.Add(x, mem)
}

/* this*=s where s is FP4 */
func (F *FP8) pmul(s *FP4, mem *arena.Arena) {
	F.a.Mul(s, mem)
	F.b.Mul(s, mem)
}

/* this*=s where s is FP2 */
func (F *FP8) qmul(s *FP2, mem *arena.Arena) {
	F.a.pmul(s, mem)
	F.b.pmul(s, mem)
}

/* this*=s where s is FP */
func (F *FP8) tmul(s *FP, mem *arena.Arena) {
	F.a.qmul(s, mem)
	F.b.qmul(s, mem)
}

/* this*=c where c is int */
func (F *FP8) imul(c int, mem *arena.Arena) {
	F.a.imul(c, mem)
	F.b.imul(c, mem)
}

/* this*=this */
func (F *FP8) Sqr(mem *arena.Arena) {
	t1 := NewFP4copy(F.a, mem)
	t2 := NewFP4copy(F.b, mem)
	t3 := NewFP4copy(F.a, mem)

	t3.Mul(F.b, mem)
	t1.Add(F.b, mem)
	t2.times_i(mem)

	t2.Add(F.a, mem)

	t1.norm()
	t2.norm()

	F.a.copy(t1)
	F.a.Mul(t2, mem)

	t2.copy(t3)
	t2.times_i(mem)
	t2.Add(t3, mem)
	t2.norm()
	t2.Neg(mem)
	F.a.Add(t2, mem)

	F.b.copy(t3)
	F.b.Add(t3, mem)

	F.norm()
}

/* this*=y */
func (F *FP8) Mul(y *FP8, mem *arena.Arena) {
	t1 := NewFP4copy(F.a, mem)
	t2 := NewFP4copy(F.b, mem)
	t3 := NewFP4(mem)
	t4 := NewFP4copy(F.b, mem)

	t1.Mul(y.a, mem)
	t2.Mul(y.b, mem)
	t3.copy(y.b)
	t3.Add(y.a, mem)
	t4.Add(F.a, mem)

	t3.norm()
	t4.norm()

	t4.Mul(t3, mem)

	t3.copy(t1)
	t3.Neg(mem)
	t4.Add(t3, mem)
	t4.norm()

	t3.copy(t2)
	t3.Neg(mem)
	F.b.copy(t4)
	F.b.Add(t3, mem)

	t2.times_i(mem)
	F.a.copy(t2)
	F.a.Add(t1, mem)

	F.norm()
}

/* convert this to hex string */
func (F *FP8) toString() string {
	return ("[" + F.a.toString() + "," + F.b.toString() + "]")
}

/* this=1/this */
func (F *FP8) Invert(h *FP, mem *arena.Arena) {
	t1 := NewFP4copy(F.a, mem)
	t2 := NewFP4copy(F.b, mem)

	t1.Sqr(mem)
	t2.Sqr(mem)
	t2.times_i(mem)
	t2.norm()
	t1.Sub(t2, mem)
	t1.norm()

	t1.Invert(h, mem)

	F.a.Mul(t1, mem)
	t1.Neg(mem)
	t1.norm()
	F.b.Mul(t1, mem)
}

/* this*=i where i = sqrt(sqrt(-1+sqrt(-1))) */
func (F *FP8) times_i(mem *arena.Arena) {
	s := NewFP4copy(F.b, mem)
	t := NewFP4copy(F.a, mem)
	s.times_i(mem)
	F.a.copy(s)
	F.b.copy(t)
	F.norm()
	if TOWER == POSITOWER {
		F.Neg(mem)
		F.norm()
	}
}

func (F *FP8) times_i2(mem *arena.Arena) {
	F.a.times_i(mem)
	F.b.times_i(mem)
}

/* this=this^p using Frobenius */
func (F *FP8) frob(f *FP2, mem *arena.Arena) {
	ff := NewFP2copy(f, mem)
	ff.Sqr(mem)
	ff.Mul_ip(mem)
	ff.norm()

	F.a.frob(ff, mem)
	F.b.frob(ff, mem)
	F.b.pmul(f, mem)
	F.b.times_i(mem)
}

/* this=this^e
func (F *FP8) pow(e *BIG) *FP8 {
	w := NewFP8copy(F)
	w.norm()
	z := NewBIGcopy(e)
	r := NewFP8int(1)
	z.norm()
	for true {
		bt := z.parity()
		z.fshr(1)
		if bt == 1 {
			r.Mul(w)
		}
		if z.IsZero() {
			break
		}
		w.Sqr()
	}
	r.reduce()
	return r
} */

/* XTR xtr_a function */
/*
func (F *FP8) xtr_A(w *FP8, y *FP8, z *FP8) {
	r := NewFP8copy(w)
	t := NewFP8copy(w)
	r.Sub(y)
	r.norm()
	r.pmul(F.a)
	t.Add(y)
	t.norm()
	t.pmul(F.b)
	t.times_i()

	F.copy(r)
	F.Add(t)
	F.Add(z)

	F.norm()
}
*/
/* XTR xtr_d function */
/*
func (F *FP8) xtr_D() {
	w := NewFP8copy(F)
	F.Sqr()
	w.conj()
	w.Add(w)
	w.norm()
	F.Sub(w)
	F.reduce()
}
*/
/* r=x^n using XTR method on traces of FP24s */
/*
func (F *FP8) xtr_pow(n *BIG) *FP8 {
	a := NewFP8int(3)
	b := NewFP8copy(F)
	c := NewFP8copy(b)
	c.xtr_D()
	t := NewFP8()
	r := NewFP8()
	sf := NewFP8copy(F)
	sf.norm()

	par := n.parity()
	v := NewBIGcopy(n)
	v.norm()
	v.fshr(1)
	if par == 0 {
		v.dec(1)
		v.norm()
	}

	nb := v.nbits()
	for i := nb - 1; i >= 0; i-- {
		if v.bit(i) != 1 {
			t.copy(b)
			sf.conj()
			c.conj()
			b.xtr_A(a, sf, c)
			sf.conj()
			c.copy(t)
			c.xtr_D()
			a.xtr_D()
		} else {
			t.copy(a)
			t.conj()
			a.copy(b)
			a.xtr_D()
			b.xtr_A(c, sf, t)
			c.xtr_D()
		}
	}
	if par == 0 {
		r.copy(c)
	} else {
		r.copy(b)
	}
	r.reduce()
	return r
}
*/
/* r=ck^a.cl^n using XTR double exponentiation method on traces of FP24s. See Stam thesis. */
/*
func (F *FP8) xtr_pow2(ck *FP8, ckml *FP8, ckm2l *FP8, a *BIG, b *BIG) *FP8 {

	e := NewBIGcopy(a)
	d := NewBIGcopy(b)
	w := NewBIGint(0)
	e.norm()
	d.norm()
	cu := NewFP8copy(ck) // can probably be passed in w/o copying
	cv := NewFP8copy(F)
	cumv := NewFP8copy(ckml)
	cum2v := NewFP8copy(ckm2l)
	r := NewFP8()
	t := NewFP8()

	f2 := 0
	for d.parity() == 0 && e.parity() == 0 {
		d.fshr(1)
		e.fshr(1)
		f2++
	}

	for Comp(d, e) != 0 {
		if Comp(d, e) > 0 {
			w.copy(e)
			w.imul(4)
			w.norm()
			if Comp(d, w) <= 0 {
				w.copy(d)
				d.copy(e)
				e.rsub(w)
				e.norm()

				t.copy(cv)
				t.xtr_A(cu, cumv, cum2v)
				cum2v.copy(cumv)
				cum2v.conj()
				cumv.copy(cv)
				cv.copy(cu)
				cu.copy(t)
			} else {
				if d.parity() == 0 {
					d.fshr(1)
					r.copy(cum2v)
					r.conj()
					t.copy(cumv)
					t.xtr_A(cu, cv, r)
					cum2v.copy(cumv)
					cum2v.xtr_D()
					cumv.copy(t)
					cu.xtr_D()
				} else {
					if e.parity() == 1 {
						d.Sub(e)
						d.norm()
						d.fshr(1)
						t.copy(cv)
						t.xtr_A(cu, cumv, cum2v)
						cu.xtr_D()
						cum2v.copy(cv)
						cum2v.xtr_D()
						cum2v.conj()
						cv.copy(t)
					} else {
						w.copy(d)
						d.copy(e)
						d.fshr(1)
						e.copy(w)
						t.copy(cumv)
						t.xtr_D()
						cumv.copy(cum2v)
						cumv.conj()
						cum2v.copy(t)
						cum2v.conj()
						t.copy(cv)
						t.xtr_D()
						cv.copy(cu)
						cu.copy(t)
					}
				}
			}
		}
		if Comp(d, e) < 0 {
			w.copy(d)
			w.imul(4)
			w.norm()
			if Comp(e, w) <= 0 {
				e.Sub(d)
				e.norm()
				t.copy(cv)
				t.xtr_A(cu, cumv, cum2v)
				cum2v.copy(cumv)
				cumv.copy(cu)
				cu.copy(t)
			} else {
				if e.parity() == 0 {
					w.copy(d)
					d.copy(e)
					d.fshr(1)
					e.copy(w)
					t.copy(cumv)
					t.xtr_D()
					cumv.copy(cum2v)
					cumv.conj()
					cum2v.copy(t)
					cum2v.conj()
					t.copy(cv)
					t.xtr_D()
					cv.copy(cu)
					cu.copy(t)
				} else {
					if d.parity() == 1 {
						w.copy(e)
						e.copy(d)
						w.Sub(d)
						w.norm()
						d.copy(w)
						d.fshr(1)
						t.copy(cv)
						t.xtr_A(cu, cumv, cum2v)
						cumv.conj()
						cum2v.copy(cu)
						cum2v.xtr_D()
						cum2v.conj()
						cu.copy(cv)
						cu.xtr_D()
						cv.copy(t)
					} else {
						d.fshr(1)
						r.copy(cum2v)
						r.conj()
						t.copy(cumv)
						t.xtr_A(cu, cv, r)
						cum2v.copy(cumv)
						cum2v.xtr_D()
						cumv.copy(t)
						cu.xtr_D()
					}
				}
			}
		}
	}
	r.copy(cv)
	r.xtr_A(cu, cumv, cum2v)
	for i := 0; i < f2; i++ {
		r.xtr_D()
	}
	r = r.xtr_pow(d)
	return r
}
*/
/* this/=2 */
func (F *FP8) div2(mem *arena.Arena) {
	F.a.div2(mem)
	F.b.div2(mem)
}

func (F *FP8) div_i(mem *arena.Arena) {
	u := NewFP4copy(F.a, mem)
	v := NewFP4copy(F.b, mem)
	u.div_i(mem)
	F.a.copy(v)
	F.b.copy(u)
	if TOWER == POSITOWER {
		F.Neg(mem)
		F.norm()
	}
}

/*
func (F *FP8) pow(b *BIG) {
	w := NewFP8copy(F);
	r := NewFP8int(1)
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
	r.reduce();
	F.copy(r);
}
*/

/* */
// Test for Quadratic Residue
func (F *FP8) qr(h *FP) int {
	mem := arena.NewArena()
	defer mem.Free()
	c := NewFP8copy(F, mem)
	c.conj(mem)
	c.Mul(F, mem)
	return c.a.qr(h)
}

// sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2))
func (F *FP8) Sqrt(h *FP, mem *arena.Arena) {
	if F.IsZero(mem) {
		return
	}

	a := NewFP4copy(F.a, mem)
	b := NewFP4(mem)
	s := NewFP4copy(F.b, mem)
	t := NewFP4copy(F.a, mem)
	hint := NewFP(mem)

	s.Sqr(mem)
	a.Sqr(mem)
	s.times_i(mem)
	s.norm()
	a.Sub(s, mem)

	s.copy(a)
	s.norm()

	s.Sqrt(h, mem)
	a.copy(t)
	b.copy(t)

	a.Add(s, mem)
	a.norm()
	a.div2(mem)

	b.copy(F.b)
	b.div2(mem)
	qr := a.qr(hint)

	// tweak hint - multiply old hint by Norm(1/Beta)^e where Beta is irreducible polynomial
	s.copy(a)
	twk := NewFPbig(NewBIGints(TWK, mem), mem)
	twk.Mul(hint, mem)
	s.div_i(mem)
	s.norm()

	a.cmove(s, 1-qr)
	hint.cmove(twk, 1-qr)

	F.a.copy(a)
	F.a.Sqrt(hint, mem)
	s.copy(a)
	s.Invert(hint, mem)
	s.Mul(F.a, mem)
	F.b.copy(s)
	F.b.Mul(b, mem)
	t.copy(F.a)

	F.a.cmove(F.b, 1-qr)
	F.b.cmove(t, 1-qr)

	sgn := F.sign(mem)
	nr := NewFP8copy(F, mem)
	nr.Neg(mem)
	nr.norm()
	F.cmove(nr, sgn)
}

/* */
