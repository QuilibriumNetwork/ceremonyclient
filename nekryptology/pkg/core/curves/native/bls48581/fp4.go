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

/* Finite Field arithmetic  Fp^4 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1)) */

package bls48581

import (
	"arena"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581/ext"
)

//import "fmt"

type FP4 struct {
	a *FP2
	b *FP2
}

func NewFP4(mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2(mem)
		F.b = NewFP2(mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2(nil)
		F.b = NewFP2(nil)
		return F
	}
}

/* Constructors */
func NewFP4int(a int, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2int(a, mem)
		F.b = NewFP2(mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2int(a, nil)
		F.b = NewFP2(nil)
		return F
	}
}

/* Constructors */
func NewFP4ints(a int, b int, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2int(a, mem)
		F.b = NewFP2int(b, mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2int(a, nil)
		F.b = NewFP2int(b, nil)
		return F
	}
}

func NewFP4copy(x *FP4, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2copy(x.a, mem)
		F.b = NewFP2copy(x.b, mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2copy(x.a, nil)
		F.b = NewFP2copy(x.b, nil)
		return F
	}
}

func NewFP4fp2s(c *FP2, d *FP2, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2copy(c, mem)
		F.b = NewFP2copy(d, mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2copy(c, nil)
		F.b = NewFP2copy(d, nil)
		return F
	}
}

func NewFP4fp2(c *FP2, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2copy(c, mem)
		F.b = NewFP2(mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2copy(c, nil)
		F.b = NewFP2(nil)
		return F
	}
}

func NewFP4fp(c *FP, mem *arena.Arena) *FP4 {
	if mem != nil {
		F := arena.New[FP4](mem)
		F.a = NewFP2fp(c, mem)
		F.b = NewFP2(mem)
		return F
	} else {
		F := new(FP4)
		F.a = NewFP2fp(c, nil)
		F.b = NewFP2(nil)
		return F
	}
}

func NewFP4rand(rng *ext.RAND) *FP4 {
	F := NewFP4fp2s(NewFP2rand(rng), NewFP2rand(rng), nil)
	return F
}

/* reduce all components of this mod Modulus */
func (F *FP4) reduce(mem *arena.Arena) {
	F.a.reduce(mem)
	F.b.reduce(mem)
}

/* normalise all components of this mod Modulus */
func (F *FP4) norm() {
	F.a.norm()
	F.b.norm()
}

/* test this==0 ? */
func (F *FP4) IsZero(mem *arena.Arena) bool {
	return F.a.IsZero(mem) && F.b.IsZero(mem)
}

func (F *FP4) islarger() int {
	if F.IsZero(nil) {
		return 0
	}
	cmp := F.b.islarger()
	if cmp != 0 {
		return cmp
	}
	return F.a.islarger()
}

func (F *FP4) ToBytes(bf []byte) {
	var t [2 * int(MODBYTES)]byte
	MB := 2 * int(MODBYTES)
	F.b.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i] = t[i]
	}
	F.a.ToBytes(t[:])
	for i := 0; i < MB; i++ {
		bf[i+MB] = t[i]
	}
}

func FP4_fromBytes(bf []byte) *FP4 {
	var t [2 * int(MODBYTES)]byte
	MB := 2 * int(MODBYTES)
	for i := 0; i < MB; i++ {
		t[i] = bf[i]
	}
	tb := FP2_fromBytes(t[:])
	for i := 0; i < MB; i++ {
		t[i] = bf[i+MB]
	}
	ta := FP2_fromBytes(t[:])
	return NewFP4fp2s(ta, tb, nil)
}

/* Conditional move */
func (F *FP4) cmove(g *FP4, d int) {
	F.a.cmove(g.a, d)
	F.b.cmove(g.b, d)
}

/* test this==1 ? */
func (F *FP4) isunity() bool {
	mem := arena.NewArena()
	defer mem.Free()
	one := NewFP2int(1, mem)
	return F.a.Equals(one) && F.b.IsZero(mem)
}

/* test is w real? That is in a+ib test b is zero */
func (F *FP4) isreal() bool {
	mem := arena.NewArena()
	defer mem.Free()
	return F.b.IsZero(mem)
}

/* extract real part a */
func (F *FP4) real() *FP2 {
	return F.a
}

func (F *FP4) geta() *FP2 {
	return F.a
}

/* extract imaginary part b */
func (F *FP4) getb() *FP2 {
	return F.b
}

/* test this=x? */
func (F *FP4) Equals(x *FP4) bool {
	return (F.a.Equals(x.a) && F.b.Equals(x.b))
}

/* copy this=x */
func (F *FP4) copy(x *FP4) {
	F.a.copy(x.a)
	F.b.copy(x.b)
}

/* set this=0 */
func (F *FP4) zero() {
	F.a.zero()
	F.b.zero()
}

/* set this=1 */
func (F *FP4) one() {
	F.a.one()
	F.b.zero()
}

/* Return sign */
func (F *FP4) sign(mem *arena.Arena) int {
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
func (F *FP4) Neg(mem *arena.Arena) {
	F.norm()
	m := NewFP2copy(F.a, mem)
	t := NewFP2(mem)
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
func (F *FP4) conj(mem *arena.Arena) {
	F.b.Neg(mem)
	F.norm()
}

/* this=-conjugate(this) */
func (F *FP4) nconj(mem *arena.Arena) {
	F.a.Neg(mem)
	F.norm()
}

/* this+=x */
func (F *FP4) Add(x *FP4, mem *arena.Arena) {
	F.a.Add(x.a, mem)
	F.b.Add(x.b, mem)
}

/* this-=x */
func (F *FP4) Sub(x *FP4, mem *arena.Arena) {
	m := NewFP4copy(x, mem)
	m.Neg(mem)
	F.Add(m, mem)
}

/* this-=x */
func (F *FP4) rsub(x *FP4, mem *arena.Arena) {
	F.Neg(mem)
	F.Add(x, mem)
}

/* this*=s where s is FP2 */
func (F *FP4) pmul(s *FP2, mem *arena.Arena) {
	F.a.Mul(s, mem)
	F.b.Mul(s, mem)
}

/* this*=s where s is FP2 */
func (F *FP4) qmul(s *FP, mem *arena.Arena) {
	F.a.pmul(s, mem)
	F.b.pmul(s, mem)
}

/* this*=c where c is int */
func (F *FP4) imul(c int, mem *arena.Arena) {
	F.a.imul(c, mem)
	F.b.imul(c, mem)
}

/* this*=this */
func (F *FP4) Sqr(mem *arena.Arena) {
	t1 := NewFP2copy(F.a, mem)
	t2 := NewFP2copy(F.b, mem)
	t3 := NewFP2copy(F.a, mem)

	t3.Mul(F.b, mem)
	t1.Add(F.b, mem)
	t2.Mul_ip(mem)

	t2.Add(F.a, mem)

	t1.norm()
	t2.norm()

	F.a.copy(t1)

	F.a.Mul(t2, mem)

	t2.copy(t3)
	t2.Mul_ip(mem)
	t2.Add(t3, mem)
	t2.norm()
	t2.Neg(mem)
	F.a.Add(t2, mem)

	F.b.copy(t3)
	F.b.Add(t3, mem)

	F.norm()
}

/* this*=y */
func (F *FP4) Mul(y *FP4, mem *arena.Arena) {
	t1 := NewFP2copy(F.a, mem)
	t2 := NewFP2copy(F.b, mem)
	t3 := NewFP2(mem)
	t4 := NewFP2copy(F.b, mem)

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

	t2.Mul_ip(mem)
	F.a.copy(t2)
	F.a.Add(t1, mem)

	F.norm()
}

/* convert this to hex string */
func (F *FP4) toString() string {
	return ("[" + F.a.toString() + "," + F.b.toString() + "]")
}

/* this=1/this */
func (F *FP4) Invert(h *FP, mem *arena.Arena) {
	t1 := NewFP2copy(F.a, mem)
	t2 := NewFP2copy(F.b, mem)

	t1.Sqr(mem)
	t2.Sqr(mem)
	t2.Mul_ip(mem)
	t2.norm()
	t1.Sub(t2, mem)

	t1.Invert(h, mem)
	F.a.Mul(t1, mem)
	t1.Neg(mem)
	t1.norm()
	F.b.Mul(t1, mem)
}

/* this*=i where i = sqrt(2^i+sqrt(-1)) */
func (F *FP4) times_i(mem *arena.Arena) {
	t := NewFP2copy(F.b, mem)
	F.b.copy(F.a)
	t.Mul_ip(mem)
	F.a.copy(t)
	F.norm()
	if TOWER == POSITOWER {
		F.Neg(mem)
		F.norm()
	}
}

/* this=this^p using Frobenius */
func (F *FP4) frob(f *FP2, mem *arena.Arena) {
	F.a.conj(mem)
	F.b.conj(mem)
	F.b.Mul(f, mem)
}

/* this=this^e
func (F *FP4) pow(e *BIG) *FP4 {
	w := NewFP4copy(F)
	w.norm()
	z := NewBIGcopy(e)
	r := NewFP4int(1)
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
}
*/
/* XTR xtr_a function */
func (F *FP4) xtr_A(w *FP4, y *FP4, z *FP4, mem *arena.Arena) {
	r := NewFP4copy(w, mem)
	t := NewFP4copy(w, mem)
	r.Sub(y, mem)
	r.norm()
	r.pmul(F.a, mem)
	t.Add(y, mem)
	t.norm()
	t.pmul(F.b, mem)
	t.times_i(mem)

	F.copy(r)
	F.Add(t, mem)
	F.Add(z, mem)

	F.norm()
}

/* XTR xtr_d function */
func (F *FP4) xtr_D(mem *arena.Arena) {
	w := NewFP4copy(F, mem)
	F.Sqr(mem)
	w.conj(mem)
	w.Add(w, mem)
	w.norm()
	F.Sub(w, mem)
	F.reduce(mem)
}

/* r=x^n using XTR method on traces of FP12s */
func (F *FP4) xtr_pow(n *BIG, mem *arena.Arena) *FP4 {
	a := NewFP4int(3, mem)
	b := NewFP4copy(F, mem)
	c := NewFP4copy(b, mem)
	c.xtr_D(mem)
	t := NewFP4(mem)
	r := NewFP4(mem)
	sf := NewFP4copy(F, mem)
	sf.norm()

	par := n.parity()
	v := NewBIGcopy(n, mem)
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
			sf.conj(mem)
			c.conj(mem)
			b.xtr_A(a, sf, c, mem)
			sf.conj(mem)
			c.copy(t)
			c.xtr_D(mem)
			a.xtr_D(mem)
		} else {
			t.copy(a)
			t.conj(mem)
			a.copy(b)
			a.xtr_D(mem)
			b.xtr_A(c, sf, t, mem)
			c.xtr_D(mem)
		}
	}
	if par == 0 {
		r.copy(c)
	} else {
		r.copy(b)
	}
	r.reduce(mem)
	return r
}

/* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
func (F *FP4) xtr_pow2(ck *FP4, ckml *FP4, ckm2l *FP4, a *BIG, b *BIG, mem *arena.Arena) *FP4 {

	e := NewBIGcopy(a, mem)
	d := NewBIGcopy(b, mem)
	w := NewBIGint(0, mem)
	e.norm()
	d.norm()

	cu := NewFP4copy(ck, mem) // can probably be passed in w/o copying
	cv := NewFP4copy(F, mem)
	cumv := NewFP4copy(ckml, mem)
	cum2v := NewFP4copy(ckm2l, mem)
	r := NewFP4(mem)
	t := NewFP4(mem)

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
				t.xtr_A(cu, cumv, cum2v, mem)
				cum2v.copy(cumv)
				cum2v.conj(mem)
				cumv.copy(cv)
				cv.copy(cu)
				cu.copy(t)
			} else {
				if d.parity() == 0 {
					d.fshr(1)
					r.copy(cum2v)
					r.conj(mem)
					t.copy(cumv)
					t.xtr_A(cu, cv, r, mem)
					cum2v.copy(cumv)
					cum2v.xtr_D(mem)
					cumv.copy(t)
					cu.xtr_D(mem)
				} else {
					if e.parity() == 1 {
						d.Sub(e)
						d.norm()
						d.fshr(1)
						t.copy(cv)
						t.xtr_A(cu, cumv, cum2v, mem)
						cu.xtr_D(mem)
						cum2v.copy(cv)
						cum2v.xtr_D(mem)
						cum2v.conj(mem)
						cv.copy(t)
					} else {
						w.copy(d)
						d.copy(e)
						d.fshr(1)
						e.copy(w)
						t.copy(cumv)
						t.xtr_D(mem)
						cumv.copy(cum2v)
						cumv.conj(mem)
						cum2v.copy(t)
						cum2v.conj(mem)
						t.copy(cv)
						t.xtr_D(mem)
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
				t.xtr_A(cu, cumv, cum2v, mem)
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
					t.xtr_D(mem)
					cumv.copy(cum2v)
					cumv.conj(mem)
					cum2v.copy(t)
					cum2v.conj(mem)
					t.copy(cv)
					t.xtr_D(mem)
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
						t.xtr_A(cu, cumv, cum2v, mem)
						cumv.conj(mem)
						cum2v.copy(cu)
						cum2v.xtr_D(mem)
						cum2v.conj(mem)
						cu.copy(cv)
						cu.xtr_D(mem)
						cv.copy(t)
					} else {
						d.fshr(1)
						r.copy(cum2v)
						r.conj(mem)
						t.copy(cumv)
						t.xtr_A(cu, cv, r, mem)
						cum2v.copy(cumv)
						cum2v.xtr_D(mem)
						cumv.copy(t)
						cu.xtr_D(mem)
					}
				}
			}
		}
	}
	r.copy(cv)
	r.xtr_A(cu, cumv, cum2v, mem)
	for i := 0; i < f2; i++ {
		r.xtr_D(mem)
	}
	r = r.xtr_pow(d, mem)
	return r
}

/* this/=2 */
func (F *FP4) div2(mem *arena.Arena) {
	F.a.div2(mem)
	F.b.div2(mem)
}

func (F *FP4) div_i(mem *arena.Arena) {
	u := NewFP2copy(F.a, mem)
	v := NewFP2copy(F.b, mem)
	u.div_ip(mem)
	F.a.copy(v)
	F.b.copy(u)
	if TOWER == POSITOWER {
		F.Neg(mem)
		F.norm()
	}
}

/*
func (F *FP4) pow(b *BIG) {
	w := NewFP4copy(F);
	r := NewFP4int(1)
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
func (F *FP4) qr(h *FP) int {
	mem := arena.NewArena()
	defer mem.Free()
	c := NewFP4copy(F, mem)
	c.conj(mem)
	c.Mul(F, mem)
	return c.a.qr(h)
}

// sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2))
func (F *FP4) Sqrt(h *FP, mem *arena.Arena) {
	if F.IsZero(mem) {
		return
	}

	a := NewFP2copy(F.a, mem)
	b := NewFP2(mem)
	s := NewFP2copy(F.b, mem)
	t := NewFP2copy(F.a, mem)
	hint := NewFP(mem)

	s.Sqr(mem)
	a.Sqr(mem)
	s.Mul_ip(mem)
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
	s.div_ip(mem)
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
	nr := NewFP4copy(F, mem)
	nr.Neg(mem)
	nr.norm()
	F.cmove(nr, sgn)
}

/* */
