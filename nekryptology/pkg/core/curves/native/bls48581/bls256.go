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

/* Boneh-Lynn-Shacham signature 256-bit API Functions */

/* Loosely (for now) following https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-02 */

// Minimal-signature-size variant

package bls48581

import "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581/ext"

//import "fmt"

const BFS int = int(MODBYTES)
const BGS int = int(MODBYTES)
const BLS_OK int = 0
const BLS_FAIL int = -1

var G2_TAB []*FP16

func ceil(a int, b int) int {
	return (((a)-1)/(b) + 1)
}

/* output u \in F_p */
func Hash_to_field(hash int, hlen int, DST []byte, M []byte, ctr int) []*FP {
	q := NewBIGints(Modulus, nil)
	nbq := q.nbits()
	L := ceil(nbq+AESKEY*8, 8)
	var u []*FP
	var fd = make([]byte, L)
	OKM := ext.XMD_Expand(hash, hlen, L*ctr, DST, M)

	for i := 0; i < ctr; i++ {
		for j := 0; j < L; j++ {
			fd[j] = OKM[i*L+j]
		}
		u = append(u, NewFPbig(DBIG_fromBytes(fd).ctmod(q, uint(8*L-nbq), nil), nil))
	}
	return u
}

/* hash a message to an ECP point, using SHA2, random oracle method */
func Bls256_hash_to_point(M []byte) *ECP {
	DST := []byte("BLS_SIG_BLS48581G1_XMD:SHA-512_SVDW_RO_NUL_")
	u := Hash_to_field(ext.MC_SHA2, HASH_TYPE, DST, M, 2)

	P := ECP_map2point(u[0])
	P1 := ECP_map2point(u[1])
	P.Add(P1, nil)
	P.Cfp()
	P.Affine(nil)
	return P
}

func Init() int {
	G := ECP8_generator()
	if G.Is_infinity(nil) {
		return BLS_FAIL
	}
	G2_TAB = precomp(G)
	return BLS_OK
}

/* generate key pair, private key S, public key W */
func KeyPairGenerate(IKM []byte, S []byte, W []byte) int {
	r := NewBIGints(CURVE_Order, nil)
	nbr := r.nbits()
	L := ceil(3*ceil(nbr, 8), 2)
	LEN := ext.InttoBytes(L, 2)
	AIKM := make([]byte, len(IKM)+1)
	for i := 0; i < len(IKM); i++ {
		AIKM[i] = IKM[i]
	}
	AIKM[len(IKM)] = 0

	G := ECP8_generator()
	if G.Is_infinity(nil) {
		return BLS_FAIL
	}
	SALT := []byte("BLS-SIG-KEYGEN-SALT-")
	PRK := ext.HKDF_Extract(ext.MC_SHA2, HASH_TYPE, SALT, AIKM)
	OKM := ext.HKDF_Expand(ext.MC_SHA2, HASH_TYPE, L, PRK, LEN)

	dx := DBIG_fromBytes(OKM[:])
	s := dx.ctmod(r, uint(8*L-nbr), nil)
	s.ToBytes(S)
	// SkToPk
	G = G2mul(G, s, nil)
	G.ToBytes(W, true)
	return BLS_OK
}

/* Sign message m using private key S to produce signature SIG */
func Core_Sign(SIG []byte, M []byte, S []byte) int {
	D := Bls256_hash_to_point(M)
	s := FromBytes(S)
	D = G1mul(D, s, nil)
	D.ToBytes(SIG, true)
	return BLS_OK
}

/* Verify signature given message M, the signature SIG, and the public key W */

func Core_Verify(SIG []byte, M []byte, W []byte) int {
	HM := Bls256_hash_to_point(M)

	D := ECP_fromBytes(SIG)
	if !G1member(D, nil) {
		return BLS_FAIL
	}
	D.Neg(nil)

	PK := ECP8_fromBytes(W)
	if !G2member(PK, nil) {
		return BLS_FAIL
	}

	// Use new multi-pairing mechanism
	r := Initmp(nil)
	Another_pc(r, G2_TAB, D)
	Another(r, PK, HM, nil)
	v := Miller(r, nil)

	//.. or alternatively
	//	G := ECP8_generator()
	//	if G.Is_infinity() {return BLS_FAIL}
	//	v := Ate2(G, D, PK, HM)

	v = Fexp(v)

	if v.Isunity() {
		return BLS_OK
	} else {
		return BLS_FAIL
	}
}
