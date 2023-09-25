//
// Copyright (c) 2019 harmony-one
//
// SPDX-License-Identifier: MIT
//

package iqc

import (
	"math/big"
)

type ClassGroup struct {
	a *big.Int
	b *big.Int
	c *big.Int
	d *big.Int
}

func NewClassGroup(a, b, c *big.Int) *ClassGroup {
	return &ClassGroup{a: a, b: b, c: c}
}

func (cg *ClassGroup) Clone() *ClassGroup {
	return &ClassGroup{a: cg.a, b: cg.b, c: cg.c}
}

func NewClassGroupFromAbDiscriminant(a, b, discriminant *big.Int) *ClassGroup {
	//z = b*b-discriminant
	z := new(big.Int).Sub(new(big.Int).Mul(b, b), discriminant)

	//z = z // 4a
	c := FloorDivision(z, new(big.Int).Mul(a, big.NewInt(4)))

	return NewClassGroup(a, b, c)
}

func NewClassGroupFromBytesDiscriminant(buf []byte, discriminant *big.Int) (*ClassGroup, bool) {
	int_size_bits := discriminant.BitLen()

	//add additional one byte for sign
	int_size := (int_size_bits + 16) >> 4

	//make sure the input byte buffer size matches with discriminant's
	if len(buf) != int_size*2 {
		return nil, false
	}

	a := decodeTwosComplement(buf[:int_size])
	b := decodeTwosComplement(buf[int_size:])
	if a.Cmp(big.NewInt(0)) == 0 {
		return nil, false
	}

	return NewClassGroupFromAbDiscriminant(a, b, discriminant), true
}

func IdentityForDiscriminant(d *big.Int) *ClassGroup {
	return NewClassGroupFromAbDiscriminant(big.NewInt(1), big.NewInt(1), d)
}

func (group *ClassGroup) Normalized() *ClassGroup {
	a := new(big.Int).Set(group.a)
	b := new(big.Int).Set(group.b)
	c := new(big.Int).Set(group.c)

	//if b > -a && b <= a:
	if (b.Cmp(new(big.Int).Neg(a)) == 1) && (b.Cmp(a) < 1) {
		return group
	}

	//r = (a - b) // (2 * a)
	r := new(big.Int).Sub(a, b)
	r = FloorDivision(r, new(big.Int).Mul(a, big.NewInt(2)))

	//b, c = b + 2 * r * a, a * r * r + b * r + c
	t := new(big.Int).Mul(big.NewInt(2), r)
	t.Mul(t, a)
	oldB := new(big.Int).Set(b)
	b.Add(b, t)

	x := new(big.Int).Mul(a, r)
	x.Mul(x, r)
	y := new(big.Int).Mul(oldB, r)
	c.Add(c, x)
	c.Add(c, y)

	return NewClassGroup(a, b, c)
}

func (group *ClassGroup) Reduced() *ClassGroup {
	g := group.Normalized()
	a := new(big.Int).Set(g.a)
	b := new(big.Int).Set(g.b)
	c := new(big.Int).Set(g.c)

	//while a > c or (a == c and b < 0):
	for (a.Cmp(c) == 1) || ((a.Cmp(c) == 0) && (b.Sign() == -1)) {
		//s = (c + b) // (c + c)
		s := new(big.Int).Add(c, b)
		s = FloorDivision(s, new(big.Int).Add(c, c))

		//a, b, c = c, -b + 2 * s * c, c * s * s - b * s + a
		oldA := new(big.Int).Set(a)
		oldB := new(big.Int).Set(b)
		a = new(big.Int).Set(c)

		b.Neg(b)
		x := new(big.Int).Mul(big.NewInt(2), s)
		x.Mul(x, c)
		b.Add(b, x)

		c.Mul(c, s)
		c.Mul(c, s)
		oldB.Mul(oldB, s)
		c.Sub(c, oldB)
		c.Add(c, oldA)
	}

	return NewClassGroup(a, b, c).Normalized()
}

func (group *ClassGroup) identity() *ClassGroup {
	return NewClassGroupFromAbDiscriminant(big.NewInt(1), big.NewInt(1), group.Discriminant())
}

func (group *ClassGroup) Discriminant() *big.Int {
	if group.d == nil {
		d := new(big.Int).Set(group.b)
		d.Mul(d, d)
		a := new(big.Int).Set(group.a)
		a.Mul(a, group.c)
		a.Mul(a, big.NewInt(4))
		d.Sub(d, a)

		group.d = d
	}
	return group.d
}

func (group *ClassGroup) Multiply(other *ClassGroup) *ClassGroup {
	//a1, b1, c1 = self.reduced()
	x := group.Reduced()

	//a2, b2, c2 = other.reduced()
	y := other.Reduced()

	//g = (b2 + b1) // 2
	g := new(big.Int).Add(x.b, y.b)
	g = FloorDivision(g, big.NewInt(2))

	//h = (b2 - b1) // 2
	h := new(big.Int).Sub(y.b, x.b)
	h = FloorDivision(h, big.NewInt(2))

	//w = mod.gcd(a1, a2, g)
	w1 := allInputValueGCD(y.a, g)
	w := allInputValueGCD(x.a, w1)

	//j = w
	j := new(big.Int).Set(w)
	//r = 0
	r := big.NewInt(0)
	//s = a1 // w
	s := FloorDivision(x.a, w)
	//t = a2 // w
	t := FloorDivision(y.a, w)
	//u = g // w
	u := FloorDivision(g, w)

	//k_temp, constant_factor = mod.solve_mod(t * u, h * u + s * c1, s * t)
	b := new(big.Int).Mul(h, u)
	sc := new(big.Int).Mul(s, x.c)
	b.Add(b, sc)
	k_temp, constant_factor, solvable := SolveMod(new(big.Int).Mul(t, u), b, new(big.Int).Mul(s, t))
	if !solvable {
		return nil
	}

	//n, constant_factor_2 = mod.solve_mod(t * constant_factor, h - t * k_temp, s)
	n, _, solvable := SolveMod(new(big.Int).Mul(t, constant_factor), new(big.Int).Sub(h, new(big.Int).Mul(t, k_temp)), s)
	if !solvable {
		return nil
	}

	//k = k_temp + constant_factor * n
	k := new(big.Int).Add(k_temp, new(big.Int).Mul(constant_factor, n))

	//l = (t * k - h) // s
	l := FloorDivision(new(big.Int).Sub(new(big.Int).Mul(t, k), h), s)

	//m = (t * u * k - h * u - s * c1) // (s * t)
	tuk := new(big.Int).Mul(t, u)
	tuk.Mul(tuk, k)

	hu := new(big.Int).Mul(h, u)

	tuk.Sub(tuk, hu)
	tuk.Sub(tuk, sc)

	st := new(big.Int).Mul(s, t)
	m := FloorDivision(tuk, st)

	//a3 = s * t - r * u
	ru := new(big.Int).Mul(r, u)
	a3 := st.Sub(st, ru)

	//b3 = (j * u + m * r) - (k * t + l * s)
	ju := new(big.Int).Mul(j, u)
	mr := new(big.Int).Mul(m, r)
	ju = ju.Add(ju, mr)

	kt := new(big.Int).Mul(k, t)
	ls := new(big.Int).Mul(l, s)
	kt = kt.Add(kt, ls)

	b3 := ju.Sub(ju, kt)

	//c3 = k * l - j * m
	kl := new(big.Int).Mul(k, l)
	jm := new(big.Int).Mul(j, m)

	c3 := kl.Sub(kl, jm)
	return NewClassGroup(a3, b3, c3).Reduced()
}

func (group *ClassGroup) Pow(n int64) *ClassGroup {
	x := group.Clone()
	items_prod := group.identity()

	for n > 0 {
		if n&1 == 1 {
			items_prod = items_prod.Multiply(x)
			if items_prod == nil {
				return nil
			}
		}
		x = x.Square()
		if x == nil {
			return nil
		}
		n >>= 1
	}
	return items_prod
}

func (group *ClassGroup) BigPow(n *big.Int) *ClassGroup {
	x := group.Clone()
	items_prod := group.identity()

	p := new(big.Int).Set(n)
	for p.Sign() > 0 {
		if p.Bit(0) == 1 {
			items_prod = items_prod.Multiply(x)
			if items_prod == nil {
				return nil
			}
		}
		x = x.Square()
		if x == nil {
			return nil
		}
		p.Rsh(p, 1)
	}
	return items_prod
}

func (group *ClassGroup) Square() *ClassGroup {
	u, _, solvable := SolveMod(group.b, group.c, group.a)
	if !solvable {
		return nil
	}

	//A = a
	A := new(big.Int).Mul(group.a, group.a)

	//B = b − 2aµ,
	au := new(big.Int).Mul(group.a, u)
	B := new(big.Int).Sub(group.b, new(big.Int).Mul(au, big.NewInt(2)))

	//C = µ ^ 2 - (bµ−c)//a
	C := new(big.Int).Mul(u, u)
	m := new(big.Int).Mul(group.b, u)
	m = new(big.Int).Sub(m, group.c)
	m = FloorDivision(m, group.a)
	C = new(big.Int).Sub(C, m)

	return NewClassGroup(A, B, C).Reduced()
}

func (group *ClassGroup) SquareUsingMultiply() *ClassGroup {
	//a1, b1, c1 = self.reduced()
	x := group.Reduced()

	//g = b1
	g := x.b
	//h = 0
	h := big.NewInt(0)

	//w = mod.gcd(a1, g)
	w := allInputValueGCD(x.a, g)

	//j = w
	j := new(big.Int).Set(w)
	//r = 0
	r := big.NewInt(0)
	//s = a1 // w
	s := FloorDivision(x.a, w)
	//t = s
	t := s
	//u = g // w
	u := FloorDivision(g, w)

	//k_temp, constant_factor = mod.solve_mod(t * u, h * u + s * c1, s * t)
	b := new(big.Int).Mul(h, u)
	sc := new(big.Int).Mul(s, x.c)
	b.Add(b, sc)
	k_temp, constant_factor, solvable := SolveMod(new(big.Int).Mul(t, u), b, new(big.Int).Mul(s, t))
	if !solvable {
		return nil
	}

	//n, constant_factor_2 = mod.solve_mod(t * constant_factor, h - t * k_temp, s)
	n, _, solvable := SolveMod(new(big.Int).Mul(t, constant_factor), new(big.Int).Sub(h, new(big.Int).Mul(t, k_temp)), s)
	if !solvable {
		return nil
	}

	//k = k_temp + constant_factor * n
	k := new(big.Int).Add(k_temp, new(big.Int).Mul(constant_factor, n))

	//l = (t * k - h) // s
	l := FloorDivision(new(big.Int).Sub(new(big.Int).Mul(t, k), h), s)

	//m = (t * u * k - h * u - s * c1) // (s * t)
	tuk := new(big.Int).Mul(t, u)
	tuk.Mul(tuk, k)

	hu := new(big.Int).Mul(h, u)

	tuk.Sub(tuk, hu)
	tuk.Sub(tuk, sc)

	st := new(big.Int).Mul(s, t)
	m := FloorDivision(tuk, st)

	//a3 = s * t - r * u
	ru := new(big.Int).Mul(r, u)
	a3 := st.Sub(st, ru)

	//b3 = (j * u + m * r) - (k * t + l * s)
	ju := new(big.Int).Mul(j, u)
	mr := new(big.Int).Mul(m, r)
	ju = ju.Add(ju, mr)

	kt := new(big.Int).Mul(k, t)
	ls := new(big.Int).Mul(l, s)
	kt = kt.Add(kt, ls)

	b3 := ju.Sub(ju, kt)

	//c3 = k * l - j * m
	kl := new(big.Int).Mul(k, l)
	jm := new(big.Int).Mul(j, m)

	c3 := kl.Sub(kl, jm)

	return NewClassGroup(a3, b3, c3).Reduced()
}

// Serialize encodes a, b based on discriminant's size
// using one more byte for sign if nessesary
func (group *ClassGroup) Serialize() []byte {
	r := group.Reduced()
	int_size_bits := group.Discriminant().BitLen()
	int_size := (int_size_bits + 16) >> 4

	buf := make([]byte, int_size*2)
	copy(buf[:int_size], signBitFill(encodeTwosComplement(r.a), int_size))
	copy(buf[int_size:], signBitFill(encodeTwosComplement(r.b), int_size))

	return buf
}

func (group *ClassGroup) Equal(other *ClassGroup) bool {
	g := group.Reduced()
	o := other.Reduced()

	return (g.a.Cmp(o.a) == 0 && g.b.Cmp(o.b) == 0 && g.c.Cmp(o.c) == 0)
}

func FloorDivision(x, y *big.Int) *big.Int {
	var r big.Int
	q, _ := new(big.Int).QuoRem(x, y, &r)

	if (r.Sign() == 1 && y.Sign() == -1) || (r.Sign() == -1 && y.Sign() == 1) {
		q.Sub(q, big.NewInt(1))
	}

	return q
}

var bigOne = big.NewInt(1)

func decodeTwosComplement(bytes []byte) *big.Int {
	if bytes[0]&0x80 == 0 {
		// non-negative
		return new(big.Int).SetBytes(bytes)
	}
	setyb := make([]byte, len(bytes))
	for i := range bytes {
		setyb[i] = bytes[i] ^ 0xff
	}
	n := new(big.Int).SetBytes(setyb)
	return n.Sub(n.Neg(n), bigOne)
}

func encodeTwosComplement(n *big.Int) []byte {
	if n.Sign() > 0 {
		bytes := n.Bytes()
		if bytes[0]&0x80 == 0 {
			return bytes
		}
		// add one more byte for positive sign
		buf := make([]byte, len(bytes)+1)
		copy(buf[1:], bytes)
		return buf
	}
	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement form. So we
		// invert and subtract 1. If the most-significant-bit isn't set then
		// we'll need to pad the beginning with 0xff in order to keep the number
		// negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		if len(bytes) == 0 {
			// sneaky -1 value
			return []byte{0xff}
		}
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if bytes[0]&0x80 != 0 {
			return bytes
		}
		// add one more byte for negative sign
		buf := make([]byte, len(bytes)+1)
		buf[0] = 0xff
		copy(buf[1:], bytes)
		return buf
	}
	return []byte{}
}

func signBitFill(bytes []byte, targetLen int) []byte {
	if len(bytes) >= targetLen {
		return bytes
	}
	buf := make([]byte, targetLen)
	offset := targetLen - len(bytes)
	if bytes[0]&0x80 != 0 {
		for i := 0; i < offset; i++ {
			buf[i] = 0xff
		}
	}
	copy(buf[offset:], bytes)
	return buf
}

func EncodeBigIntBigEndian(a *big.Int) []byte {
	int_size_bits := a.BitLen()
	int_size := (int_size_bits + 16) >> 3

	return signBitFill(encodeTwosComplement(a), int_size)
}

// Return r, s, t such that gcd(a, b) = r = a * s + b * t
func extendedGCD(a, b *big.Int) (r, s, t *big.Int) {
	//r0, r1 = a, b
	r0 := new(big.Int).Set(a)
	r1 := new(big.Int).Set(b)

	//s0, s1, t0, t1 = 1, 0, 0, 1
	s0 := big.NewInt(1)
	s1 := big.NewInt(0)
	t0 := big.NewInt(0)
	t1 := big.NewInt(1)

	//if r0 > r1:
	//r0, r1, s0, s1, t0, t1 = r1, r0, t0, t1, s0, s1
	if r0.Cmp(r1) == 1 {
		oldR0 := new(big.Int).Set(r0)
		r0 = r1
		r1 = oldR0
		oldS0 := new(big.Int).Set(s0)
		s0 = t0
		oldS1 := new(big.Int).Set(s1)
		s1 = t1
		t0 = oldS0
		t1 = oldS1
	}

	//while r1 > 0:
	for r1.Sign() == 1 {
		//q, r = divmod(r0, r1)
		r := big.NewInt(1)
		bb := new(big.Int).Set(b)
		q, r := bb.DivMod(r0, r1, r)

		//r0, r1, s0, s1, t0, t1 = r1, r, s1, s0 - q * s1, t1, t0 - q * t1
		r0 = r1
		r1 = r
		oldS0 := new(big.Int).Set(s0)
		s0 = s1
		s1 = new(big.Int).Sub(oldS0, new(big.Int).Mul(q, s1))
		oldT0 := new(big.Int).Set(t0)
		t0 = t1
		t1 = new(big.Int).Sub(oldT0, new(big.Int).Mul(q, t1))

	}
	return r0, s0, t0
}

// wrapper around big.Int GCD to allow all input values for GCD
// as Golang big.Int GCD requires both a, b > 0
// If a == b == 0, GCD sets r = 0.
// If a == 0 and b != 0, GCD sets r = |b|
// If a != 0 and b == 0, GCD sets r = |a|
// Otherwise r = GCD(|a|, |b|)
func allInputValueGCD(a, b *big.Int) (r *big.Int) {
	if a.Sign() == 0 {
		return new(big.Int).Abs(b)
	}

	if b.Sign() == 0 {
		return new(big.Int).Abs(a)
	}

	return new(big.Int).GCD(nil, nil, new(big.Int).Abs(a), new(big.Int).Abs(b))
}

// Solve ax == b mod m for x.
// Return s, t where x = s + k * t for integer k yields all solutions.
func SolveMod(a, b, m *big.Int) (s, t *big.Int, solvable bool) {
	//g, d, e = extended_gcd(a, m)
	//TODO: golang 1.x big.int GCD requires both a > 0 and m > 0, so we can't use it :(
	//d := big.NewInt(0)
	//e := big.NewInt(0)
	//g := new(big.Int).GCD(d, e, a, m)
	g, d, _ := extendedGCD(a, m)
	if g.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, false
	}

	//q, r = divmod(b, g)
	r := big.NewInt(1)
	bb := new(big.Int).Set(b)
	q, r := bb.DivMod(b, g, r)

	//TODO: replace with utils.GetLogInstance().Error(...)
	//if r != 0:
	if r.Cmp(big.NewInt(0)) != 0 {
		//panic(fmt.Sprintf("no solution to %s x = %s mod %s", a.String(), b.String(), m.String()))
		return nil, nil, false
	}

	//assert b == q * g
	//return (q * d) % m, m // g
	q.Mul(q, d)
	s = q.Mod(q, m)
	t = FloorDivision(m, g)
	return s, t, true
}
