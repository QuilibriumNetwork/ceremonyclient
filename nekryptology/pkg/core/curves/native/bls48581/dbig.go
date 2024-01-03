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

/* MiotCL double length DBIG number class */

package bls48581

import (
	"arena"
	"strconv"
)

//import "fmt"

func NewDBIG(mem *arena.Arena) *DBIG {
	var b *DBIG
	if mem != nil {
		b = arena.New[DBIG](mem)
	} else {
		b = new(DBIG)
	}
	for i := 0; i < DNLEN; i++ {
		b.w[i] = 0
	}
	return b
}

func NewDBIGcopy(x *DBIG, mem *arena.Arena) *DBIG {
	var b *DBIG
	if mem != nil {
		b = arena.New[DBIG](mem)
	} else {
		b = new(DBIG)
	}
	for i := 0; i < DNLEN; i++ {
		b.w[i] = x.w[i]
	}
	return b
}

func NewDBIGscopy(x *BIG, mem *arena.Arena) *DBIG {
	var b *DBIG
	if mem != nil {
		b = arena.New[DBIG](mem)
	} else {
		b = new(DBIG)
	}
	for i := 0; i < NLEN-1; i++ {
		b.w[i] = x.w[i]
	}
	b.w[NLEN-1] = x.get(NLEN-1) & BMASK /* top word normalized */
	b.w[NLEN] = x.get(NLEN-1) >> BASEBITS

	for i := NLEN + 1; i < DNLEN; i++ {
		b.w[i] = 0
	}
	return b
}

/* normalise this */
func (r *DBIG) norm() {
	carry := Chunk(0)
	for i := 0; i < DNLEN-1; i++ {
		d := r.w[i] + carry
		r.w[i] = d & BMASK
		carry = d >> BASEBITS
	}
	r.w[DNLEN-1] = (r.w[DNLEN-1] + carry)
}

/* split DBIG at position n, return higher half, keep lower half */
func (r *DBIG) split(n uint, mem *arena.Arena) *BIG {
	t := NewBIG(mem)
	m := n % BASEBITS
	carry := r.w[DNLEN-1] << (BASEBITS - m)

	for i := DNLEN - 2; i >= NLEN-1; i-- {
		nw := (r.w[i] >> m) | carry
		carry = (r.w[i] << (BASEBITS - m)) & BMASK
		t.set(i-NLEN+1, nw)
	}
	r.w[NLEN-1] &= ((Chunk(1) << m) - 1)
	return t
}

func (r *DBIG) cmove(g *DBIG, d int) Chunk {
	var b = Chunk(-d)
	s := Chunk(0)
	v := r.w[0] ^ g.w[1]
	va := v + v
	va >>= 1
	for i := 0; i < DNLEN; i++ {
		t := (r.w[i] ^ g.w[i]) & b
		t ^= v
		e := r.w[i] ^ t
		s ^= e
		r.w[i] = e ^ va
	}
	return s
}

/* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
func dcomp(a *DBIG, b *DBIG) int {
	gt := Chunk(0)
	eq := Chunk(1)
	for i := DNLEN - 1; i >= 0; i-- {
		gt |= ((b.w[i] - a.w[i]) >> BASEBITS) & eq
		eq &= ((b.w[i] ^ a.w[i]) - 1) >> BASEBITS
	}
	return int(gt + gt + eq - 1)
}

/* Copy from another DBIG */
func (r *DBIG) copy(x *DBIG) {
	for i := 0; i < DNLEN; i++ {
		r.w[i] = x.w[i]
	}
}

/* Copy from another BIG to upper half */
func (r *DBIG) ucopy(x *BIG) {
	for i := 0; i < NLEN; i++ {
		r.w[i] = 0
	}
	for i := NLEN; i < DNLEN; i++ {
		r.w[i] = x.w[i-NLEN]
	}
}

func (r *DBIG) Add(x *DBIG) {
	for i := 0; i < DNLEN; i++ {
		r.w[i] = r.w[i] + x.w[i]
	}
}

/* this-=x */
func (r *DBIG) Sub(x *DBIG) {
	for i := 0; i < DNLEN; i++ {
		r.w[i] = r.w[i] - x.w[i]
	}
}

/* this-=x */
func (r *DBIG) rsub(x *DBIG) {
	for i := 0; i < DNLEN; i++ {
		r.w[i] = x.w[i] - r.w[i]
	}
}

/* general shift left */
func (r *DBIG) shl(k uint) {
	n := k % BASEBITS
	m := int(k / BASEBITS)

	r.w[DNLEN-1] = (r.w[DNLEN-1-m] << n) | (r.w[DNLEN-m-2] >> (BASEBITS - n))
	for i := DNLEN - 2; i > m; i-- {
		r.w[i] = ((r.w[i-m] << n) & BMASK) | (r.w[i-m-1] >> (BASEBITS - n))
	}
	r.w[m] = (r.w[0] << n) & BMASK
	for i := 0; i < m; i++ {
		r.w[i] = 0
	}
}

/* general shift right */
func (r *DBIG) shr(k uint) {
	n := (k % BASEBITS)
	m := int(k / BASEBITS)
	for i := 0; i < DNLEN-m-1; i++ {
		r.w[i] = (r.w[m+i] >> n) | ((r.w[m+i+1] << (BASEBITS - n)) & BMASK)
	}
	r.w[DNLEN-m-1] = r.w[DNLEN-1] >> n
	for i := DNLEN - m; i < DNLEN; i++ {
		r.w[i] = 0
	}
}

func (r *DBIG) ctmod(m *BIG, bd uint, mem *arena.Arena) *BIG {
	k := bd
	r.norm()
	c := NewDBIGscopy(m, mem)
	dr := NewDBIG(mem)

	c.shl(k)

	for {
		dr.copy(r)
		dr.Sub(c)
		dr.norm()
		r.cmove(dr, int(1-((dr.w[DNLEN-1]>>uint(CHUNK-1))&1)))
		if k == 0 {
			break
		}
		k -= 1
		c.shr(1)
	}
	return NewBIGdcopy(r, mem)
}

/* reduces this DBIG mod a BIG, and returns the BIG */
func (r *DBIG) Mod(m *BIG, mem *arena.Arena) *BIG {
	k := r.nbits() - m.nbits()
	if k < 0 {
		k = 0
	}
	return r.ctmod(m, uint(k), mem)
}

func (r *DBIG) ctdiv(m *BIG, bd uint, mem *arena.Arena) *BIG {
	k := bd
	c := NewDBIGscopy(m, mem)
	a := NewBIGint(0, mem)
	e := NewBIGint(1, mem)
	sr := NewBIG(mem)
	dr := NewDBIG(mem)
	r.norm()

	c.shl(k)
	e.shl(k)

	for {
		dr.copy(r)
		dr.Sub(c)
		dr.norm()
		d := int(1 - ((dr.w[DNLEN-1] >> uint(CHUNK-1)) & 1))
		r.cmove(dr, d)
		sr.copy(a)
		sr.Add(e)
		sr.norm()
		a.cmove(sr, d)
		if k == 0 {
			break
		}
		k -= 1
		c.shr(1)
		e.shr(1)
	}
	return a
}

/* return this/c */
func (r *DBIG) div(m *BIG, mem *arena.Arena) *BIG {
	k := r.nbits() - m.nbits()
	if k < 0 {
		k = 0
	}
	return r.ctdiv(m, uint(k), mem)
}

/* Convert to Hex String */
func (r *DBIG) toString() string {
	s := ""
	len := r.nbits()

	if len%4 == 0 {
		len /= 4
	} else {
		len /= 4
		len++

	}

	for i := len - 1; i >= 0; i-- {
		b := NewDBIGcopy(r, nil)

		b.shr(uint(i * 4))
		s += strconv.FormatInt(int64(b.w[0]&15), 16)
	}
	return s
}

/* return number of bits */
func (r *DBIG) nbits() int {
	k := DNLEN - 1
	t := NewDBIGcopy(r, nil)
	t.norm()
	for k >= 0 && t.w[k] == 0 {
		k--
	}
	if k < 0 {
		return 0
	}
	bts := int(BASEBITS) * k
	c := t.w[k]
	for c != 0 {
		c /= 2
		bts++
	}
	return bts
}

/* convert from byte array to BIG */
func DBIG_fromBytes(b []byte) *DBIG {
	m := NewDBIG(nil)
	for i := 0; i < len(b); i++ {
		m.shl(8)
		m.w[0] += Chunk(int(b[i] & 0xff))
	}
	return m
}
