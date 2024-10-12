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

//import "fmt"
/* Elliptic Curve Point Structure */

type ECP struct {
	x *FP
	y *FP
	z *FP
}

/* Constructors */
func NewECP() *ECP {
	E := new(ECP)
	E.x = NewFP()
	E.y = NewFPint(1)
	if CURVETYPE == EDWARDS {
		E.z = NewFPint(1)
	} else {
		E.z = NewFP()
	}
	return E
}

/* set (x,y) from two BIGs */
func NewECPbigs(ix *BIG, iy *BIG) *ECP {
	E := new(ECP)
	E.x = NewFPbig(ix)
	E.y = NewFPbig(iy)
	E.z = NewFPint(1)
	E.x.norm()
	rhs := RHS(E.x)

	if CURVETYPE == MONTGOMERY {
		if rhs.qr(nil) != 1 {
			E.inf()
		}
	} else {
		y2 := NewFPcopy(E.y)
		y2.Sqr()
		if !y2.Equals(rhs) {
			E.inf()
		}
	}
	return E
}

/* set (x,y) from BIG and a bit */
func NewECPbigint(ix *BIG, s int) *ECP {
	E := new(ECP)
	E.x = NewFPbig(ix)
	E.y = NewFP()
	E.x.norm()
	rhs := RHS(E.x)
	E.z = NewFPint(1)
	hint := NewFP()
	if rhs.qr(hint) == 1 {
		ny := rhs.Sqrt(hint)
		if ny.sign() != s {
			ny.Neg()
			ny.norm()
		}
		E.y.copy(ny)
	} else {
		E.inf()
	}
	return E
}

/* set from x - calculate y from curve equation */
func NewECPbig(ix *BIG) *ECP {
	E := new(ECP)
	E.x = NewFPbig(ix)
	E.y = NewFP()
	E.x.norm()
	rhs := RHS(E.x)
	E.z = NewFPint(1)
	hint := NewFP()
	if rhs.qr(hint) == 1 {
		if CURVETYPE != MONTGOMERY {
			E.y.copy(rhs.Sqrt(hint))
		}
	} else {
		E.inf()
	}
	return E
}

/* test for O point-at-infinity */
func (E *ECP) Is_infinity() bool {
	//	if E.INF {return true}

	if CURVETYPE == EDWARDS {
		return (E.x.IsZero() && E.y.Equals(E.z))
	}
	if CURVETYPE == WEIERSTRASS {
		return (E.x.IsZero() && E.z.IsZero())
	}
	if CURVETYPE == MONTGOMERY {
		return E.z.IsZero()
	}
	return true
}

/* Conditional swap of P and Q dependant on d */
func (E *ECP) cswap(Q *ECP, d int) {
	E.x.cswap(Q.x, d)
	if CURVETYPE != MONTGOMERY {
		E.y.cswap(Q.y, d)
	}
	E.z.cswap(Q.z, d)
}

/* Conditional move of Q to P dependant on d */
func (E *ECP) cmove(Q *ECP, d int) {
	E.x.cmove(Q.x, d)
	if CURVETYPE != MONTGOMERY {
		E.y.cmove(Q.y, d)
	}
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
	if CURVETYPE != MONTGOMERY {
		E.y.copy(P.y)
	}
	E.z.copy(P.z)
}

/* this=-this */
func (E *ECP) Neg() {
	if CURVETYPE == WEIERSTRASS {
		E.y.Neg()
		E.y.norm()
	}
	if CURVETYPE == EDWARDS {
		E.x.Neg()
		E.x.norm()
	}
	return
}

/* Constant time select from pre-computed table */
func (E *ECP) selector(W []*ECP, b int32) {
	MP := NewECP()
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
	MP.Neg()
	E.cmove(MP, int(m&1))
}

/* set this=O */
func (E *ECP) inf() {
	E.x.zero()
	if CURVETYPE != MONTGOMERY {
		E.y.one()
	}
	if CURVETYPE != EDWARDS {
		E.z.zero()
	} else {
		E.z.one()
	}
}

/* Test P == Q */
func (E *ECP) Equals(Q *ECP) bool {
	a := NewFP()
	b := NewFP()
	a.copy(E.x)
	a.Mul(Q.z)
	a.reduce()
	b.copy(Q.x)
	b.Mul(E.z)
	b.reduce()
	if !a.Equals(b) {
		return false
	}
	if CURVETYPE != MONTGOMERY {
		a.copy(E.y)
		a.Mul(Q.z)
		a.reduce()
		b.copy(Q.y)
		b.Mul(E.z)
		b.reduce()
		if !a.Equals(b) {
			return false
		}
	}

	return true
}

/* Calculate RHS of curve equation */
func RHS(x *FP) *FP {
	r := NewFPcopy(x)
	r.Sqr()

	if CURVETYPE == WEIERSTRASS { // x^3+Ax+B
		b := NewFPbig(NewBIGints(CURVE_B))
		r.Mul(x)
		if CURVE_A == -3 {
			cx := NewFPcopy(x)
			cx.imul(3)
			cx.Neg()
			cx.norm()
			r.Add(cx)
		}
		r.Add(b)
	}
	if CURVETYPE == EDWARDS { // (Ax^2-1)/(Bx^2-1)
		b := NewFPbig(NewBIGints(CURVE_B))

		one := NewFPint(1)
		b.Mul(r)
		b.Sub(one)
		b.norm()
		if CURVE_A == -1 {
			r.Neg()
		}
		r.Sub(one)
		r.norm()
		b.Invert(nil)
		r.Mul(b)
	}
	if CURVETYPE == MONTGOMERY { // x^3+Ax^2+x
		x3 := NewFP()
		x3.copy(r)
		x3.Mul(x)
		r.imul(CURVE_A)
		r.Add(x3)
		r.Add(x)
	}
	r.reduce()
	return r
}

/* set to affine - from (x,y,z) to (x,y) */
func (E *ECP) Affine() {
	if E.Is_infinity() {
		return
	}
	one := NewFPint(1)
	if E.z.Equals(one) {
		return
	}
	E.z.Invert(nil)
	E.x.Mul(E.z)
	E.x.reduce()

	if CURVETYPE != MONTGOMERY {
		E.y.Mul(E.z)
		E.y.reduce()
	}
	E.z.copy(one)
}

/* extract x as a BIG */
func (E *ECP) GetX() *BIG {
	W := NewECP()
	W.Copy(E)
	W.Affine()
	return W.x.Redc()
}

/* extract y as a BIG */
func (E *ECP) GetY() *BIG {
	W := NewECP()
	W.Copy(E)
	W.Affine()
	return W.y.Redc()
}

/* get sign of Y */
func (E *ECP) GetS() int {
	W := NewECP()
	W.Copy(E)
	W.Affine()
	return W.y.sign()
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
	alt := false
	W := NewECP()
	W.Copy(E)
	W.Affine()
	W.x.Redc().ToBytes(t[:])

	if CURVETYPE == MONTGOMERY {
		for i := 0; i < MB; i++ {
			b[i] = t[i]
		}
		//b[0] = 0x06
		return
	}

	if (MODBITS-1)%8 <= 4 && ALLOW_ALT_COMPRESS {
		alt = true
	}

	if alt {
		for i := 0; i < MB; i++ {
			b[i] = t[i]
		}
		if compress {
			b[0] |= 0x80
			if W.y.islarger() == 1 {
				b[0] |= 0x20
			}
		} else {
			W.y.Redc().ToBytes(t[:])
			for i := 0; i < MB; i++ {
				b[i+MB] = t[i]
			}
		}
	} else {
		for i := 0; i < MB; i++ {
			b[i+1] = t[i]
		}
		if compress {
			b[0] = 0x02
			if W.y.sign() == 1 {
				b[0] = 0x03
			}
			return
		}
		b[0] = 0x04
		W.y.Redc().ToBytes(t[:])
		for i := 0; i < MB; i++ {
			b[i+MB+1] = t[i]
		}
	}
}

/* convert from byte array to point */
func ECP_fromBytes(b []byte) *ECP {
	var t [int(MODBYTES)]byte
	MB := int(MODBYTES)
	p := NewBIGints(Modulus)
	alt := false

	if CURVETYPE == MONTGOMERY {
		for i := 0; i < MB; i++ {
			t[i] = b[i]
		}
		px := FromBytes(t[:])
		if Comp(px, p) >= 0 {
			return NewECP()
		}
		return NewECPbig(px)
	}

	if (MODBITS-1)%8 <= 4 && ALLOW_ALT_COMPRESS {
		alt = true
	}

	if alt {
		for i := 0; i < MB; i++ {
			t[i] = b[i]
		}
		t[0] &= 0x1f
		px := FromBytes(t[:])
		if (b[0] & 0x80) == 0 {
			for i := 0; i < MB; i++ {
				t[i] = b[i+MB]
			}
			py := FromBytes(t[:])
			return NewECPbigs(px, py)
		} else {
			sgn := (b[0] & 0x20) >> 5
			P := NewECPbigint(px, 0)
			cmp := P.y.islarger()
			if (sgn == 1 && cmp != 1) || (sgn == 0 && cmp == 1) {
				P.Neg()
			}
			return P
		}
	} else {
		for i := 0; i < MB; i++ {
			t[i] = b[i+1]
		}
		px := FromBytes(t[:])
		if Comp(px, p) >= 0 {
			return NewECP()
		}

		if b[0] == 0x04 {
			for i := 0; i < MB; i++ {
				t[i] = b[i+MB+1]
			}
			py := FromBytes(t[:])
			if Comp(py, p) >= 0 {
				return NewECP()
			}
			return NewECPbigs(px, py)
		}

		if b[0] == 0x02 || b[0] == 0x03 {
			return NewECPbigint(px, int(b[0]&1))
		}
	}
	return NewECP()
}

/* convert to hex string */
func (E *ECP) ToString() string {
	W := NewECP()
	W.Copy(E)
	W.Affine()
	if W.Is_infinity() {
		return "infinity"
	}
	if CURVETYPE == MONTGOMERY {
		return "(" + W.x.Redc().ToString() + ")"
	} else {
		return "(" + W.x.Redc().ToString() + "," + W.y.Redc().ToString() + ")"
	}
}

/* this*=2 */
func (E *ECP) Dbl() {

	if CURVETYPE == WEIERSTRASS {
		if CURVE_A == 0 {
			t0 := NewFPcopy(E.y)
			t0.Sqr()
			t1 := NewFPcopy(E.y)
			t1.Mul(E.z)
			t2 := NewFPcopy(E.z)
			t2.Sqr()

			E.z.copy(t0)
			E.z.Add(t0)
			E.z.norm()
			E.z.Add(E.z)
			E.z.Add(E.z)
			E.z.norm()
			t2.imul(3 * CURVE_B_I)

			x3 := NewFPcopy(t2)
			x3.Mul(E.z)

			y3 := NewFPcopy(t0)
			y3.Add(t2)
			y3.norm()
			E.z.Mul(t1)
			t1.copy(t2)
			t1.Add(t2)
			t2.Add(t1)
			t0.Sub(t2)
			t0.norm()
			y3.Mul(t0)
			y3.Add(x3)
			t1.copy(E.x)
			t1.Mul(E.y)
			E.x.copy(t0)
			E.x.norm()
			E.x.Mul(t1)
			E.x.Add(E.x)
			E.x.norm()
			E.y.copy(y3)
			E.y.norm()
		} else {
			t0 := NewFPcopy(E.x)
			t1 := NewFPcopy(E.y)
			t2 := NewFPcopy(E.z)
			t3 := NewFPcopy(E.x)
			z3 := NewFPcopy(E.z)
			y3 := NewFP()
			x3 := NewFP()
			b := NewFP()

			if CURVE_B_I == 0 {
				b.copy(NewFPbig(NewBIGints(CURVE_B)))
			}

			t0.Sqr() //1    x^2
			t1.Sqr() //2    y^2
			t2.Sqr() //3

			t3.Mul(E.y) //4
			t3.Add(t3)
			t3.norm()   //5
			z3.Mul(E.x) //6
			z3.Add(z3)
			z3.norm() //7
			y3.copy(t2)

			if CURVE_B_I == 0 {
				y3.Mul(b)
			} else {
				y3.imul(CURVE_B_I)
			}

			y3.Sub(z3) //9  ***
			x3.copy(y3)
			x3.Add(y3)
			x3.norm() //10

			y3.Add(x3) //11
			x3.copy(t1)
			x3.Sub(y3)
			x3.norm() //12
			y3.Add(t1)
			y3.norm()  //13
			y3.Mul(x3) //14
			x3.Mul(t3) //15
			t3.copy(t2)
			t3.Add(t2) //16
			t2.Add(t3) //17

			if CURVE_B_I == 0 {
				z3.Mul(b)
			} else {
				z3.imul(CURVE_B_I)
			}

			z3.Sub(t2) //19
			z3.Sub(t0)
			z3.norm() //20  ***
			t3.copy(z3)
			t3.Add(z3) //21

			z3.Add(t3)
			z3.norm() //22
			t3.copy(t0)
			t3.Add(t0) //23
			t0.Add(t3) //24
			t0.Sub(t2)
			t0.norm() //25

			t0.Mul(z3) //26
			y3.Add(t0) //27
			t0.copy(E.y)
			t0.Mul(E.z) //28
			t0.Add(t0)
			t0.norm()  //29
			z3.Mul(t0) //30
			x3.Sub(z3) //x3.norm();//31
			t0.Add(t0)
			t0.norm() //32
			t1.Add(t1)
			t1.norm() //33
			z3.copy(t0)
			z3.Mul(t1) //34

			E.x.copy(x3)
			E.x.norm()
			E.y.copy(y3)
			E.y.norm()
			E.z.copy(z3)
			E.z.norm()
		}
	}

	if CURVETYPE == EDWARDS {
		C := NewFPcopy(E.x)
		D := NewFPcopy(E.y)
		H := NewFPcopy(E.z)
		J := NewFP()

		E.x.Mul(E.y)
		E.x.Add(E.x)
		E.x.norm()
		C.Sqr()
		D.Sqr()
		if CURVE_A == -1 {
			C.Neg()
		}
		E.y.copy(C)
		E.y.Add(D)
		E.y.norm()

		H.Sqr()
		H.Add(H)
		E.z.copy(E.y)
		J.copy(E.y)
		J.Sub(H)
		J.norm()
		E.x.Mul(J)
		C.Sub(D)
		C.norm()
		E.y.Mul(C)
		E.z.Mul(J)

	}
	if CURVETYPE == MONTGOMERY {
		A := NewFPcopy(E.x)
		B := NewFPcopy(E.x)
		AA := NewFP()
		BB := NewFP()
		C := NewFP()

		A.Add(E.z)
		A.norm()
		AA.copy(A)
		AA.Sqr()
		B.Sub(E.z)
		B.norm()
		BB.copy(B)
		BB.Sqr()
		C.copy(AA)
		C.Sub(BB)
		C.norm()

		E.x.copy(AA)
		E.x.Mul(BB)

		A.copy(C)
		A.imul((CURVE_A + 2) / 4)

		BB.Add(A)
		BB.norm()
		E.z.copy(BB)
		E.z.Mul(C)
	}
	return
}

/* this+=Q */
func (E *ECP) Add(Q *ECP) {

	if CURVETYPE == WEIERSTRASS {
		if CURVE_A == 0 {
			b := 3 * CURVE_B_I
			t0 := NewFPcopy(E.x)
			t0.Mul(Q.x)
			t1 := NewFPcopy(E.y)
			t1.Mul(Q.y)
			t2 := NewFPcopy(E.z)
			t2.Mul(Q.z)
			t3 := NewFPcopy(E.x)
			t3.Add(E.y)
			t3.norm()
			t4 := NewFPcopy(Q.x)
			t4.Add(Q.y)
			t4.norm()
			t3.Mul(t4)
			t4.copy(t0)
			t4.Add(t1)

			t3.Sub(t4)
			t3.norm()
			t4.copy(E.y)
			t4.Add(E.z)
			t4.norm()
			x3 := NewFPcopy(Q.y)
			x3.Add(Q.z)
			x3.norm()

			t4.Mul(x3)
			x3.copy(t1)
			x3.Add(t2)

			t4.Sub(x3)
			t4.norm()
			x3.copy(E.x)
			x3.Add(E.z)
			x3.norm()
			y3 := NewFPcopy(Q.x)
			y3.Add(Q.z)
			y3.norm()
			x3.Mul(y3)
			y3.copy(t0)
			y3.Add(t2)
			y3.rsub(x3)
			y3.norm()
			x3.copy(t0)
			x3.Add(t0)
			t0.Add(x3)
			t0.norm()
			t2.imul(b)

			z3 := NewFPcopy(t1)
			z3.Add(t2)
			z3.norm()
			t1.Sub(t2)
			t1.norm()
			y3.imul(b)

			x3.copy(y3)
			x3.Mul(t4)
			t2.copy(t3)
			t2.Mul(t1)
			x3.rsub(t2)
			y3.Mul(t0)
			t1.Mul(z3)
			y3.Add(t1)
			t0.Mul(t3)
			z3.Mul(t4)
			z3.Add(t0)

			E.x.copy(x3)
			E.x.norm()
			E.y.copy(y3)
			E.y.norm()
			E.z.copy(z3)
			E.z.norm()
		} else {

			t0 := NewFPcopy(E.x)
			t1 := NewFPcopy(E.y)
			t2 := NewFPcopy(E.z)
			t3 := NewFPcopy(E.x)
			t4 := NewFPcopy(Q.x)
			z3 := NewFP()
			y3 := NewFPcopy(Q.x)
			x3 := NewFPcopy(Q.y)
			b := NewFP()

			if CURVE_B_I == 0 {
				b.copy(NewFPbig(NewBIGints(CURVE_B)))
			}

			t0.Mul(Q.x) //1
			t1.Mul(Q.y) //2
			t2.Mul(Q.z) //3

			t3.Add(E.y)
			t3.norm() //4
			t4.Add(Q.y)
			t4.norm()  //5
			t3.Mul(t4) //6
			t4.copy(t0)
			t4.Add(t1) //7
			t3.Sub(t4)
			t3.norm() //8
			t4.copy(E.y)
			t4.Add(E.z)
			t4.norm() //9
			x3.Add(Q.z)
			x3.norm()  //10
			t4.Mul(x3) //11
			x3.copy(t1)
			x3.Add(t2) //12

			t4.Sub(x3)
			t4.norm() //13
			x3.copy(E.x)
			x3.Add(E.z)
			x3.norm() //14
			y3.Add(Q.z)
			y3.norm() //15

			x3.Mul(y3) //16
			y3.copy(t0)
			y3.Add(t2) //17

			y3.rsub(x3)
			y3.norm() //18
			z3.copy(t2)

			if CURVE_B_I == 0 {
				z3.Mul(b)
			} else {
				z3.imul(CURVE_B_I)
			}

			x3.copy(y3)
			x3.Sub(z3)
			x3.norm() //20
			z3.copy(x3)
			z3.Add(x3) //21

			x3.Add(z3) //22
			z3.copy(t1)
			z3.Sub(x3)
			z3.norm() //23
			x3.Add(t1)
			x3.norm() //24

			if CURVE_B_I == 0 {
				y3.Mul(b)
			} else {
				y3.imul(CURVE_B_I)
			}

			t1.copy(t2)
			t1.Add(t2) //26
			t2.Add(t1) //27

			y3.Sub(t2) //28

			y3.Sub(t0)
			y3.norm() //29
			t1.copy(y3)
			t1.Add(y3) //30
			y3.Add(t1)
			y3.norm() //31

			t1.copy(t0)
			t1.Add(t0) //32
			t0.Add(t1) //33
			t0.Sub(t2)
			t0.norm() //34
			t1.copy(t4)
			t1.Mul(y3) //35
			t2.copy(t0)
			t2.Mul(y3) //36
			y3.copy(x3)
			y3.Mul(z3) //37
			y3.Add(t2) //38
			x3.Mul(t3) //39
			x3.Sub(t1) //40
			z3.Mul(t4) //41
			t1.copy(t3)
			t1.Mul(t0) //42
			z3.Add(t1)
			E.x.copy(x3)
			E.x.norm()
			E.y.copy(y3)
			E.y.norm()
			E.z.copy(z3)
			E.z.norm()

		}
	}
	if CURVETYPE == EDWARDS {
		b := NewFPbig(NewBIGints(CURVE_B))
		A := NewFPcopy(E.z)
		B := NewFP()
		C := NewFPcopy(E.x)
		D := NewFPcopy(E.y)
		EE := NewFP()
		F := NewFP()
		G := NewFP()

		A.Mul(Q.z)
		B.copy(A)
		B.Sqr()
		C.Mul(Q.x)
		D.Mul(Q.y)

		EE.copy(C)
		EE.Mul(D)
		EE.Mul(b)
		F.copy(B)
		F.Sub(EE)
		G.copy(B)
		G.Add(EE)

		if CURVE_A == 1 {
			EE.copy(D)
			EE.Sub(C)
		}
		C.Add(D)

		B.copy(E.x)
		B.Add(E.y)
		D.copy(Q.x)
		D.Add(Q.y)
		B.norm()
		D.norm()
		B.Mul(D)
		B.Sub(C)
		B.norm()
		F.norm()
		B.Mul(F)
		E.x.copy(A)
		E.x.Mul(B)
		G.norm()
		if CURVE_A == 1 {
			EE.norm()
			C.copy(EE)
			C.Mul(G)
		}
		if CURVE_A == -1 {
			C.norm()
			C.Mul(G)
		}
		E.y.copy(A)
		E.y.Mul(C)
		E.z.copy(F)
		E.z.Mul(G)
	}
	return
}

/* Differential Add for Montgomery curves. this+=Q where W is this-Q and is affine. */
func (E *ECP) dAdd(Q *ECP, W *ECP) {
	A := NewFPcopy(E.x)
	B := NewFPcopy(E.x)
	C := NewFPcopy(Q.x)
	D := NewFPcopy(Q.x)
	DA := NewFP()
	CB := NewFP()

	A.Add(E.z)
	B.Sub(E.z)

	C.Add(Q.z)
	D.Sub(Q.z)
	A.norm()
	D.norm()

	DA.copy(D)
	DA.Mul(A)
	C.norm()
	B.norm()

	CB.copy(C)
	CB.Mul(B)

	A.copy(DA)
	A.Add(CB)
	A.norm()
	A.Sqr()
	B.copy(DA)
	B.Sub(CB)
	B.norm()
	B.Sqr()

	E.x.copy(A)
	E.z.copy(W.x)
	E.z.Mul(B)

}

/* this-=Q */
func (E *ECP) Sub(Q *ECP) {
	NQ := NewECP()
	NQ.Copy(Q)
	NQ.Neg()
	E.Add(NQ)
}

/* constant time multiply by small integer of length bts - use lAdder */
func (E *ECP) pinmul(e int32, bts int32) *ECP {
	if CURVETYPE == MONTGOMERY {
		return E.lmul(NewBIGint(int(e)))
	} else {
		P := NewECP()
		R0 := NewECP()
		R1 := NewECP()
		R1.Copy(E)

		for i := bts - 1; i >= 0; i-- {
			b := int((e >> uint32(i)) & 1)
			P.Copy(R1)
			P.Add(R0)
			R0.cswap(R1, b)
			R1.Copy(P)
			R0.Dbl()
			R0.cswap(R1, b)
		}
		P.Copy(R0)
		return P
	}
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
func (E *ECP) lmul(e *BIG) *ECP {
	return E.clmul(e, e)
}

// .. but this one does not (typically set maxe=r)
// Set P=e*P
/* return e.this */
func (E *ECP) clmul(e *BIG, maxe *BIG) *ECP {
	if e.IsZero() || E.Is_infinity() {
		return NewECP()
	}
	P := NewECP()
	cm := NewBIGcopy(e)
	cm.or(maxe)
	max := cm.nbits()

	if CURVETYPE == MONTGOMERY {
		/* use LAdder */
		D := NewECP()
		R0 := NewECP()
		R0.Copy(E)
		R1 := NewECP()
		R1.Copy(E)
		R1.Dbl()
		D.Copy(E)
		D.Affine()
		nb := max
		for i := nb - 2; i >= 0; i-- {
			b := int(e.bit(i))
			P.Copy(R1)
			P.dAdd(R0, D)
			R0.cswap(R1, b)
			R1.Copy(P)
			R0.Dbl()
			R0.cswap(R1, b)
		}
		P.Copy(R0)
	} else {
		// fixed size windows
		mt := NewBIG()
		t := NewBIG()
		Q := NewECP()
		C := NewECP()

		var W []*ECP
		var w [1 + (NLEN*int(BASEBITS)+3)/4]int8

		Q.Copy(E)
		Q.Dbl()

		W = append(W, NewECP())
		W[0].Copy(E)

		for i := 1; i < 8; i++ {
			W = append(W, NewECP())
			W[i].Copy(W[i-1])
			W[i].Add(Q)
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
			P.Dbl()
			P.Dbl()
			P.Dbl()
			P.Dbl()
			P.Add(Q)
		}
		P.Sub(C) /* apply correction */
	}
	return P
}

/* Public version */
func (E *ECP) Mul(e *BIG) *ECP {
	return E.lmul(e)
}

// Generic multi-multiplication, fixed 4-bit window, P=Sigma e_i*X_i
func ECP_muln(n int, X []*ECP, e []*BIG) *ECP {
	P := NewECP()
	R := NewECP()
	S := NewECP()
	var B []*ECP
	t := NewBIG()
	for i := 0; i < 16; i++ {
		B = append(B, NewECP())
	}
	mt := NewBIGcopy(e[0])
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
		for j := 0; j < n; j++ {
			mt.copy(e[j])
			mt.norm()
			mt.shr(uint(i * 4))
			k := mt.lastbits(4)
			B[k].Add(X[j])
		}
		R.inf()
		S.inf()
		for j := 15; j >= 1; j-- {
			R.Add(B[j])
			S.Add(R)
		}
		for j := 0; j < 4; j++ {
			P.Dbl()
		}
		P.Add(S)
	}
	return P
}

/* Return e.this+f.Q */

func (E *ECP) Mul2(e *BIG, Q *ECP, f *BIG) *ECP {
	te := NewBIG()
	tf := NewBIG()
	mt := NewBIG()
	S := NewECP()
	T := NewECP()
	C := NewECP()
	var W []*ECP
	var w [1 + (NLEN*int(BASEBITS)+1)/2]int8

	te.copy(e)
	tf.copy(f)

	// precompute table
	for i := 0; i < 8; i++ {
		W = append(W, NewECP())
	}
	W[1].Copy(E)
	W[1].Sub(Q)
	W[2].Copy(E)
	W[2].Add(Q)
	S.Copy(Q)
	S.Dbl()
	W[0].Copy(W[1])
	W[0].Sub(S)
	W[3].Copy(W[2])
	W[3].Add(S)
	T.Copy(E)
	T.Dbl()
	W[5].Copy(W[1])
	W[5].Add(T)
	W[6].Copy(W[2])
	W[6].Add(T)
	W[4].Copy(W[5])
	W[4].Sub(S)
	W[7].Copy(W[6])
	W[7].Add(S)

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
	C.Add(S)

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
		S.Dbl()
		S.Dbl()
		S.Add(T)
	}
	S.Sub(C) /* apply correction */
	return S
}

func (E *ECP) Cfp() {
	cf := CURVE_Cof_I
	if cf == 1 {
		return
	}
	if cf == 4 {
		E.Dbl()
		E.Dbl()
		return
	}
	if cf == 8 {
		E.Dbl()
		E.Dbl()
		E.Dbl()
		return
	}
	c := NewBIGints(CURVE_Cof)
	E.Copy(E.lmul(c))
}

/* Hunt and Peck a BIG to a curve point */
func ECP_hap2point(h *BIG) *ECP {
	var P *ECP
	x := NewBIGcopy(h)

	for true {
		if CURVETYPE != MONTGOMERY {
			P = NewECPbigint(x, 0)
		} else {
			P = NewECPbig(x)
		}
		x.inc(1)
		x.norm()
		if !P.Is_infinity() {
			break
		}
	}
	return P
}

/* Constant time Map to Point */
func ECP_map2point(h *FP) *ECP {
	P := NewECP()

	if CURVETYPE == MONTGOMERY {
		// Elligator 2
		X1 := NewFP()
		X2 := NewFP()
		w := NewFP()
		one := NewFPint(1)
		A := NewFPint(CURVE_A)
		t := NewFPcopy(h)
		N := NewFP()
		D := NewFP()
		hint := NewFP()

		t.Sqr()

		if PM1D2 == 2 {
			t.Add(t)
		}
		if PM1D2 == 1 {
			t.Neg()
		}
		if PM1D2 > 2 {
			t.imul(QNRI)
		}

		t.norm()
		D.copy(t)
		D.Add(one)
		D.norm()

		X1.copy(A)
		X1.Neg()
		X1.norm()
		X2.copy(X1)
		X2.Mul(t)

		w.copy(X1)
		w.Sqr()
		N.copy(w)
		N.Mul(X1)
		w.Mul(A)
		w.Mul(D)
		N.Add(w)
		t.copy(D)
		t.Sqr()
		t.Mul(X1)
		N.Add(t)
		N.norm()

		t.copy(N)
		t.Mul(D)
		qres := t.qr(hint)
		w.copy(t)
		w.Invert(hint)
		D.copy(w)
		D.Mul(N)
		X1.Mul(D)
		X2.Mul(D)
		X1.cmove(X2, 1-qres)

		a := X1.Redc()
		P.Copy(NewECPbig(a))
	}
	if CURVETYPE == EDWARDS {
		// Elligator 2 - map to Montgomery, place point, map back
		X1 := NewFP()
		X2 := NewFP()
		t := NewFPcopy(h)
		w := NewFP()
		one := NewFPint(1)
		A := NewFP()
		w1 := NewFP()
		w2 := NewFP()
		B := NewFPbig(NewBIGints(CURVE_B))
		Y := NewFP()
		K := NewFP()
		D := NewFP()
		hint := NewFP()
		//Y3:=NewFP()
		rfc := 0

		if MODTYPE != GENERALISED_MERSENNE {
			A.copy(B)

			if CURVE_A == 1 {
				A.Add(one)
				B.Sub(one)
			} else {
				A.Sub(one)
				B.Add(one)
			}
			A.norm()
			B.norm()

			A.div2()
			B.div2()
			B.div2()

			K.copy(B)
			K.Neg()
			K.norm()
			//K.Invert(nil)
			K.invsqrt(K, w1)

			rfc = RIADZ
			if rfc == 1 { // RFC7748
				A.Mul(K)
				K.Mul(w1)
				//K=K.Sqrt(nil)
			} else {
				B.Sqr()
			}
		} else {
			rfc = 1
			A.copy(NewFPint(156326))
		}

		t.Sqr()
		qnr := 0
		if PM1D2 == 2 {
			t.Add(t)
			qnr = 2
		}
		if PM1D2 == 1 {
			t.Neg()
			qnr = -1
		}
		if PM1D2 > 2 {
			t.imul(QNRI)
			qnr = QNRI
		}
		t.norm()

		D.copy(t)
		D.Add(one)
		D.norm()
		X1.copy(A)
		X1.Neg()
		X1.norm()
		X2.copy(X1)
		X2.Mul(t)

		// Figure out RHS of Montgomery curve in rational form gx1/d^3

		w.copy(X1)
		w.Sqr()
		w1.copy(w)
		w1.Mul(X1)
		w.Mul(A)
		w.Mul(D)
		w1.Add(w)
		w2.copy(D)
		w2.Sqr()

		if rfc == 0 {
			w.copy(X1)
			w.Mul(B)
			w2.Mul(w)
			w1.Add(w2)
		} else {
			w2.Mul(X1)
			w1.Add(w2)
		}
		w1.norm()

		B.copy(w1)
		B.Mul(D)
		qres := B.qr(hint)
		w.copy(B)
		w.Invert(hint)
		D.copy(w)
		D.Mul(w1)
		X1.Mul(D)
		X2.Mul(D)
		D.Sqr()

		w1.copy(B)
		w1.imul(qnr)
		w.copy(NewFPbig(NewBIGints(CURVE_HTPC)))
		w.Mul(hint)
		w2.copy(D)
		w2.Mul(h)

		X1.cmove(X2, 1-qres)
		B.cmove(w1, 1-qres)
		hint.cmove(w, 1-qres)
		D.cmove(w2, 1-qres)

		Y.copy(B.Sqrt(hint))
		Y.Mul(D)

		/*
						Y.copy(B.Sqrt(hint))
						Y.Mul(D)

			B.imul(qnr)
			w.copy(NewFPbig(NewBIGints(CURVE_HTPC)))
			hint.Mul(w)

						Y3.copy(B.Sqrt(hint))
						D.Mul(h)
						Y3.Mul(D)

						X1.cmove(X2,1-qres)
						Y.cmove(Y3,1-qres)
		*/
		w.copy(Y)
		w.Neg()
		w.norm()
		Y.cmove(w, qres^Y.sign())

		if rfc == 0 {
			X1.Mul(K)
			Y.Mul(K)
		}

		if MODTYPE == GENERALISED_MERSENNE {
			t.copy(X1)
			t.Sqr()
			w.copy(t)
			w.Add(one)
			w.norm()
			t.Sub(one)
			t.norm()
			w1.copy(t)
			w1.Mul(Y)
			w1.Add(w1)
			X2.copy(w1)
			X2.Add(w1)
			X2.norm()
			t.Sqr()
			Y.Sqr()
			Y.Add(Y)
			Y.Add(Y)
			Y.norm()
			B.copy(t)
			B.Add(Y)
			B.norm()

			w2.copy(Y)
			w2.Sub(t)
			w2.norm()
			w2.Mul(X1)
			t.Mul(X1)
			Y.div2()
			w1.copy(Y)
			w1.Mul(w)
			w1.rsub(t)
			w1.norm()

			t.copy(X2)
			t.Mul(w1)
			P.x.copy(t)
			t.copy(w2)
			t.Mul(B)
			P.y.copy(t)
			t.copy(w1)
			t.Mul(B)
			P.z.copy(t)

			return P
		} else {
			w1.copy(X1)
			w1.Add(one)
			w1.norm()
			w2.copy(X1)
			w2.Sub(one)
			w2.norm()
			t.copy(w1)
			t.Mul(Y)
			X1.Mul(w1)

			if rfc == 1 {
				X1.Mul(K)
			}
			Y.Mul(w2)
			P.x.copy(X1)
			P.y.copy(Y)
			P.z.copy(t)

			return P
		}
	}
	if CURVETYPE == WEIERSTRASS {
		// swu method
		A := NewFP()
		B := NewFP()
		X1 := NewFP()
		X2 := NewFP()
		X3 := NewFP()
		one := NewFPint(1)
		Y := NewFP()
		D := NewFP()
		t := NewFPcopy(h)
		w := NewFP()
		D2 := NewFP()
		hint := NewFP()
		GX1 := NewFP()
		//Y3:=NewFP()
		sgn := t.sign()

		if CURVE_A != 0 || HTC_ISO != 0 {
			if HTC_ISO != 0 {
				/* CAHCZS
									 A.copy(NewFPbig(NewBIGints(CURVE_Ad)))
									 B.copy(NewFPbig(NewBIGints(CURVE_Bd)))
				 CAHCZF */
			} else {
				A.copy(NewFPint(CURVE_A))
				B.copy(NewFPbig(NewBIGints(CURVE_B)))
			}
			// SSWU method
			t.Sqr()
			t.imul(RIADZ)
			w.copy(t)
			w.Add(one)
			w.norm()

			w.Mul(t)
			D.copy(A)
			D.Mul(w)

			w.Add(one)
			w.norm()
			w.Mul(B)
			w.Neg()
			w.norm()

			X2.copy(w)
			X3.copy(t)
			X3.Mul(X2)

			// x^3+Ad^2x+Bd^3
			GX1.copy(X2)
			GX1.Sqr()
			D2.copy(D)
			D2.Sqr()
			w.copy(A)
			w.Mul(D2)
			GX1.Add(w)
			GX1.norm()
			GX1.Mul(X2)
			D2.Mul(D)
			w.copy(B)
			w.Mul(D2)
			GX1.Add(w)
			GX1.norm()

			w.copy(GX1)
			w.Mul(D)
			qr := w.qr(hint)
			D.copy(w)
			D.Invert(hint)
			D.Mul(GX1)
			X2.Mul(D)
			X3.Mul(D)
			t.Mul(h)
			D2.copy(D)
			D2.Sqr()

			D.copy(D2)
			D.Mul(t)
			t.copy(w)
			t.imul(RIADZ)
			X1.copy(NewFPbig(NewBIGints(CURVE_HTPC)))
			X1.Mul(hint)

			X2.cmove(X3, 1-qr)
			D2.cmove(D, 1-qr)
			w.cmove(t, 1-qr)
			hint.cmove(X1, 1-qr)

			Y.copy(w.Sqrt(hint))
			Y.Mul(D2)
			/*
				Y.copy(w.Sqrt(hint))
				Y.Mul(D2)

				D2.Mul(t)
				w.imul(RIADZ)

				X1.copy(NewFPbig(NewBIGints(CURVE_HTPC)))
				hint.Mul(X1)

				Y3.copy(w.Sqrt(hint))
				Y3.Mul(D2)

				X2.cmove(X3,1-qr)
				Y.cmove(Y3,1-qr)
			*/
			ne := Y.sign() ^ sgn
			w.copy(Y)
			w.Neg()
			w.norm()
			Y.cmove(w, ne)

			if HTC_ISO != 0 {
				/* CAHCZS
									 k:=0
									 isox:=HTC_ISO
									 isoy:=3*(isox-1)/2

								 //xnum
									 xnum:=NewFPbig(NewBIGints(PC[k])); k+=1
									 for i:=0;i<isox;i++ {
										 xnum.Mul(X2)
										 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
										 xnum.Add(w); xnum.norm()
									 }
								 //xden
									 xden:=NewFPcopy(X2)
									 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
									 xden.Add(w);xden.norm();
									 for i:=0;i<isox-2;i++ {
										 xden.Mul(X2)
										 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
										 xden.Add(w); xden.norm()
									 }
								 //ynum
									 ynum:=NewFPbig(NewBIGints(PC[k])); k+=1
									 for i:=0;i<isoy;i++ {
										 ynum.Mul(X2)
										 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
										 ynum.Add(w); ynum.norm()
									 }
									 yden:=NewFPcopy(X2)
									 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
									 yden.Add(w);yden.norm();
									 for i:=0;i<isoy-1;i++ {
										 yden.Mul(X2)
										 w.copy(NewFPbig(NewBIGints(PC[k]))); k+=1
										 yden.Add(w); yden.norm()
									 }
									 ynum.Mul(Y)
									 w.copy(xnum); w.Mul(yden)
									 P.x.copy(w)
									 w.copy(ynum); w.Mul(xden)
									 P.y.copy(w)
									 w.copy(xden); w.Mul(yden)
									 P.z.copy(w)
									 return P
				 CAHCZF */
			} else {
				x := X2.Redc()
				y := Y.Redc()
				P.Copy(NewECPbigs(x, y))
				return P
			}
		} else {
			// Shallue and van de Woestijne
			// SQRTm3 not available, so preprocess this out
			/* */
			Z := RIADZ
			X1.copy(NewFPint(Z))
			X3.copy(X1)
			A.copy(RHS(X1))
			B.copy(NewFPbig(NewBIGints(SQRTm3)))
			B.imul(Z)

			t.Sqr()
			Y.copy(A)
			Y.Mul(t)
			t.copy(one)
			t.Add(Y)
			t.norm()
			Y.rsub(one)
			Y.norm()
			D.copy(t)
			D.Mul(Y)
			D.Mul(B)

			w.copy(A)
			FP_tpo(D, w)

			w.Mul(B)
			if w.sign() == 1 {
				w.Neg()
				w.norm()
			}

			w.Mul(B)
			w.Mul(h)
			w.Mul(Y)
			w.Mul(D)

			X1.Neg()
			X1.norm()
			X1.div2()
			X2.copy(X1)
			X1.Sub(w)
			X1.norm()
			X2.Add(w)
			X2.norm()
			A.Add(A)
			A.Add(A)
			A.norm()
			t.Sqr()
			t.Mul(D)
			t.Sqr()
			A.Mul(t)
			X3.Add(A)
			X3.norm()

			rhs := RHS(X2)
			X3.cmove(X2, rhs.qr(nil))
			rhs.copy(RHS(X1))
			X3.cmove(X1, rhs.qr(nil))
			rhs.copy(RHS(X3))
			Y.copy(rhs.Sqrt(nil))

			ne := Y.sign() ^ sgn
			w.copy(Y)
			w.Neg()
			w.norm()
			Y.cmove(w, ne)

			x := X3.Redc()
			y := Y.Redc()
			P.Copy(NewECPbigs(x, y))
			return P
			/* */
		}
	}
	return P
}

func ECP_mapit(h []byte) *ECP {
	q := NewBIGints(Modulus)
	dx := DBIG_fromBytes(h[:])
	x := dx.Mod(q)

	P := ECP_hap2point(x)
	P.Cfp()
	return P
}

func ECP_generator() *ECP {
	var G *ECP

	gx := NewBIGints(CURVE_Gx)
	if CURVETYPE != MONTGOMERY {
		gy := NewBIGints(CURVE_Gy)
		G = NewECPbigs(gx, gy)
	} else {
		G = NewECPbig(gx)
	}
	return G
}
