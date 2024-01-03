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

/* Finite Field arithmetic  Fp^16 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1)) */

package bls48581

import "arena"

//import "fmt"

type FP16 struct {
	a *FP8
	b *FP8
}

func NewFP16(mem *arena.Arena) *FP16 {
	if mem != nil {
		F := arena.New[FP16](mem)
		F.a = NewFP8(mem)
		F.b = NewFP8(mem)
		return F
	} else {
		F := new(FP16)
		F.a = NewFP8(nil)
		F.b = NewFP8(nil)
		return F
	}
}

/* Constructors */
func NewFP16int(a int, mem *arena.Arena) *FP16 {
	if mem != nil {
		F := arena.New[FP16](mem)
		F.a = NewFP8int(a, mem)
		F.b = NewFP8(mem)
		return F
	} else {
		F := new(FP16)
		F.a = NewFP8int(a, nil)
		F.b = NewFP8(nil)
		return F
	}
}

func NewFP16copy(x *FP16, mem *arena.Arena) *FP16 {
	if mem != nil {
		F := arena.New[FP16](mem)
		F.a = NewFP8copy(x.a, mem)
		F.b = NewFP8copy(x.b, mem)
		return F
	} else {
		F := new(FP16)
		F.a = NewFP8copy(x.a, nil)
		F.b = NewFP8copy(x.b, nil)
		return F
	}
}

func NewFP16fp8s(c *FP8, d *FP8, mem *arena.Arena) *FP16 {
	if mem != nil {
		F := arena.New[FP16](mem)
		F.a = c
		F.b = d
		return F
	} else {
		F := new(FP16)
		F.a = c
		F.b = d
		return F
	}
}

func NewFP16fp8(c *FP8, mem *arena.Arena) *FP16 {
	if mem != nil {
		F := arena.New[FP16](mem)
		F.a = c
		F.b = NewFP8(mem)
		return F
	} else {
		F := new(FP16)
		F.a = c
		F.b = NewFP8(nil)
		return F
	}
}

/* reduce all components of this mod Modulus */
func (F *FP16) reduce(mem *arena.Arena) {
	F.a.reduce(mem)
	F.b.reduce(mem)
}

/* normalise all components of this mod Modulus */
func (F *FP16) norm() {
	F.a.norm()
	F.b.norm()
}

/* test this==0 ? */
func (F *FP16) IsZero(mem *arena.Arena) bool {
	return F.a.IsZero(mem) && F.b.IsZero(mem)
}

func (F *FP16) ToBytes(bf []byte) {
	var t [8 * int(MODBYTES)]byte
	MB := 8 * int(MODBYTES)
	F.b.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i] = t[i]
	}
	F.a.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i+MB] = t[i]
	}
}

func FP16_fromBytes(bf []byte) *FP16 {
	var t [8 * int(MODBYTES)]byte
	MB := 8 * int(MODBYTES)
	for i := 0; i < MB; i++ {
		t[i] = bf[i]
	}
	tb := FP8_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = bf[i+MB]
	}
	ta := FP8_fromBytes(t[:])
	return NewFP16fp8s(ta, tb, nil)
}

/* Conditional move */
func (F *FP16) cmove(g *FP16, d int) {
	F.a.cmove(g.a, d)
	F.b.cmove(g.b, d)
}

/* test this==1 ? */
func (F *FP16) isunity() bool {
	mem := arena.NewArena()
	defer mem.Free()
	one := NewFP8int(1, mem)
	return F.a.Equals(one) && F.b.IsZero(mem)
}

/* test is w real? That is in a+ib test b is zero */
func (F *FP16) isreal() bool {
	return F.b.IsZero(nil)
}

/* extract real part a */
func (F *FP16) real() *FP8 {
	return F.a
}

func (F *FP16) geta() *FP8 {
	return F.a
}

/* extract imaginary part b */
func (F *FP16) getb() *FP8 {
	return F.b
}

/* test this=x? */
func (F *FP16) Equals(x *FP16) bool {
	return (F.a.Equals(x.a) && F.b.Equals(x.b))
}

/* copy this=x */
func (F *FP16) copy(x *FP16) {
	F.a.copy(x.a)
	F.b.copy(x.b)
}

/* set this=0 */
func (F *FP16) zero() {
	F.a.zero()
	F.b.zero()
}

/* set this=1 */
func (F *FP16) one() {
	F.a.one()
	F.b.zero()
}

/* set this=-this */
func (F *FP16) Neg(mem *arena.Arena) {
	F.norm()
	m := NewFP8copy(F.a, mem)
	t := NewFP8(mem)
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
func (F *FP16) conj(mem *arena.Arena) {
	F.b.Neg(mem)
	F.norm()
}

/* this=-conjugate(this) */
func (F *FP16) nconj(mem *arena.Arena) {
	F.a.Neg(mem)
	F.norm()
}

/* this+=x */
func (F *FP16) Add(x *FP16, mem *arena.Arena) {
	F.a.Add(x.a, mem)
	F.b.Add(x.b, mem)
}

/* this-=x */
func (F *FP16) Sub(x *FP16, mem *arena.Arena) {
	m := NewFP16copy(x, mem)
	m.Neg(mem)
	F.Add(m, mem)
}

/* this-=x */
func (F *FP16) rsub(x *FP16, mem *arena.Arena) {
	F.Neg(mem)
	F.Add(x, mem)
}

/* this*=s where s is FP8 */
func (F *FP16) pmul(s *FP8, mem *arena.Arena) {
	F.a.Mul(s, mem)
	F.b.Mul(s, mem)
}

/* this*=s where s is FP2 */
func (F *FP16) qmul(s *FP2, mem *arena.Arena) {
	F.a.qmul(s, mem)
	F.b.qmul(s, mem)
}

/* this*=s where s is FP */
func (F *FP16) tmul(s *FP, mem *arena.Arena) {
	F.a.tmul(s, mem)
	F.b.tmul(s, mem)
}

/* this*=c where c is int */
func (F *FP16) imul(c int, mem *arena.Arena) {
	F.a.imul(c, mem)
	F.b.imul(c, mem)
}

/* this*=this */
func (F *FP16) Sqr(mem *arena.Arena) {
	t1 := NewFP8copy(F.a, mem)
	t2 := NewFP8copy(F.b, mem)
	t3 := NewFP8copy(F.a, mem)

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
func (F *FP16) Mul(y *FP16, mem *arena.Arena) {
	t1 := NewFP8copy(F.a, mem)
	t2 := NewFP8copy(F.b, mem)
	t3 := NewFP8(mem)
	t4 := NewFP8copy(F.b, mem)

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
func (F *FP16) toString() string {
	return ("[" + F.a.toString() + "," + F.b.toString() + "]")
}

/* this=1/this */
func (F *FP16) Invert(mem *arena.Arena) {
	t1 := NewFP8copy(F.a, mem)
	t2 := NewFP8copy(F.b, mem)

	t1.Sqr(mem)
	t2.Sqr(mem)
	t2.times_i(mem)
	t2.norm()
	t1.Sub(t2, mem)
	t1.norm()

	t1.Invert(nil, mem)

	F.a.Mul(t1, mem)
	t1.Neg(mem)
	t1.norm()
	F.b.Mul(t1, mem)
}

/* this*=i where i = sqrt(sqrt(-1+sqrt(-1))) */
func (F *FP16) times_i(mem *arena.Arena) {
	s := NewFP8copy(F.b, mem)
	t := NewFP8copy(F.a, mem)
	s.times_i(mem)
	F.a.copy(s)
	F.b.copy(t)
	F.norm()
}

func (F *FP16) times_i2(mem *arena.Arena) {
	F.a.times_i(mem)
	F.b.times_i(mem)
}

func (F *FP16) times_i4(mem *arena.Arena) {
	F.a.times_i2(mem)
	F.b.times_i2(mem)
}

/* this=this^p using Frobenius */
func (F *FP16) frob(f *FP2, mem *arena.Arena) {
	ff := NewFP2copy(f, mem)
	ff.Sqr(mem)
	ff.norm()

	F.a.frob(ff, mem)
	F.b.frob(ff, mem)
	F.b.qmul(f, mem)
	F.b.times_i(mem)

}

/* this=this^e */
func (F *FP16) pow(e *BIG, mem *arena.Arena) *FP16 {
	w := NewFP16copy(F, mem)
	w.norm()
	z := NewBIGcopy(e, mem)
	r := NewFP16int(1, mem)
	z.norm()
	for true {
		bt := z.parity()
		z.fshr(1)
		if bt == 1 {
			r.Mul(w, mem)
		}
		if z.IsZero() {
			break
		}
		w.Sqr(mem)
	}
	r.reduce(mem)
	return r
}

/* XTR xtr_a function */
/*
func (F *FP16) xtr_A(w *FP16, y *FP16, z *FP16) {
	r := NewFP16copy(w)
	t := NewFP16copy(w)
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
func (F *FP16) xtr_D() {
	w := NewFP16copy(F)
	F.Sqr()
	w.conj()
	w.Add(w)
	w.norm()
	F.Sub(w)
	F.reduce()
}
*/
/* r=x^n using XTR method on traces of FP48s */
/*
func (F *FP16) xtr_pow(n *BIG) *FP16 {
	sf := NewFP16copy(F)
	sf.norm()
	a := NewFP16int(3)
	b := NewFP16copy(sf)
	c := NewFP16copy(b)
	c.xtr_D()
	t := NewFP16()
	r := NewFP16()

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
/* r=ck^a.cl^n using XTR double exponentiation method on traces of FP48s. See Stam thesis. */
/*
func (F *FP16) xtr_pow2(ck *FP16, ckml *FP16, ckm2l *FP16, a *BIG, b *BIG) *FP16 {

	e := NewBIGcopy(a)
	d := NewBIGcopy(b)
	w := NewBIGint(0)
	e.norm()
	d.norm()
	cu := NewFP16copy(ck) // can probably be passed in w/o copying
	cv := NewFP16copy(F)
	cumv := NewFP16copy(ckml)
	cum2v := NewFP16copy(ckm2l)
	r := NewFP16()
	t := NewFP16()

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
