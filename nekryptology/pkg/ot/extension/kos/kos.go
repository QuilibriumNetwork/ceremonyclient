//
// Copyright Coinbase, Inc. All Rights Reserved.
// Copyright Quilibrium, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package kos in an implementation of maliciously secure OT extension protocol defined in "Protocol 9" of
// [DKLs18](https://eprint.iacr.org/2018/499.pdf). The original protocol was presented in
// [KOS15](https://eprint.iacr.org/2015/546.pdf).
package kos

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/base/simplest"
)

type Receiver struct {
	Kappa                     uint
	KappaBytes                uint
	L                         uint
	COtBlockSizeBytes         uint
	OtWidth                   uint
	s                         uint
	kappaOT                   uint
	lPrime                    uint
	cOtExtendedBlockSizeBytes uint

	// OutputAdditiveShares are the ultimate output received. basically just the "pads".
	OutputAdditiveShares [][]curves.Scalar

	// seedOtResults are the results that this party has received by playing the sender role in a base OT protocol.
	seedOtResults *simplest.SenderOutput

	// extendedPackedChoices is storage for "choice vector || gamma^{ext}" in a packed format.
	extendedPackedChoices []byte
	psi                   [][]byte // transpose of v^0. gets retained between messages

	curve           *curves.Curve
	uniqueSessionId [simplest.DigestSize]byte // store this between rounds
}

type Sender struct {
	Kappa                     uint
	KappaBytes                uint
	L                         uint
	COtBlockSizeBytes         uint
	OtWidth                   uint
	s                         uint
	kappaOT                   uint
	lPrime                    uint
	cOtExtendedBlockSizeBytes uint

	// OutputAdditiveShares are the ultimate output received. basically just the "pads".
	OutputAdditiveShares [][]curves.Scalar

	// seedOtResults are the results that this party has received by playing the receiver role in a base OT protocol.
	seedOtResults *simplest.ReceiverOutput

	curve *curves.Curve
}

func binaryFieldMul(A []byte, B []byte) []byte {
	// multiplies `A` and `B` in the finite field of order 2^256.
	// The reference is Hankerson, Vanstone and Menezes, Guide to Elliptic Curve Cryptography. https://link.springer.com/book/10.1007/b97644
	// `A` and `B` are both assumed to be 32-bytes slices. here we view them as little-endian coordinate representations of degree-255 polynomials.
	// the multiplication takes place modulo the irreducible (over F_2) polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1. see Table A.1.
	// x^512 + x^8 + x^5 + 2
	// x^1024 + x^19 + x^6 + x + 1
	// the techniques we use are given in section 2.3, Binary field arithmetic.
	// for the multiplication part, we use Algorithm 2.34, "Right-to-left comb method for polynomial multiplication".
	// for the reduction part, we use a variant of the idea of Figure 2.9, customized to our setting.
	const W = 64             // the machine word width, in bits.
	const t = 4              // the number of words needed to represent a polynomial.
	c := make([]uint64, 2*t) // result
	a := make([]uint64, t)
	b := make([]uint64, t+1)  // will hold a copy of b, shifted by some amount
	for i := 0; i < 32; i++ { // "condense" `A` and `B` into word-vectors, instead of byte-vectors
		a[i>>3] |= uint64(A[i]) << (i & 0x07 << 3)
		b[i>>3] |= uint64(B[i]) << (i & 0x07 << 3)
	}
	for k := 0; k < W; k++ {
		for j := 0; j < t; j++ {
			// conditionally add a copy of (the appropriately shifted) B to C, depending on the appropriate bit of A
			// do this in constant-time; i.e., independent of A.
			// technically, in each time we call this, the right-hand argument is a public datum,
			// so we could arrange things so that it's _not_ constant-time, but the variable-time stuff always depends on something public.
			// better to just be safe here though and make it constant-time anyway.
			mask := -(a[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFFFFFFFFFFFFFFF else 0x0000000000000000
			for i := 0; i < t+1; i++ {
				c[j+i] ^= b[i] & mask // conditionally add B to C{j}
			}
		}
		for i := t; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// multiplication complete; begin reduction.
	// things become actually somewhat simpler in our case, because the degree of the polynomial is a multiple of the word size
	// the technique to come up with the numbers below comes essentially from going through the exact same process as on page 54,
	// but with the polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1 above instead, and with parameters m = 256, W = 64, t = 4.
	// the idea is exactly as described informally on that page, even though this particular polynomial isn't explicitly treated.
	for i := 2*t - 1; i >= t; i-- {
		c[i-4] ^= c[i] << 10
		c[i-3] ^= c[i] >> 54
		c[i-4] ^= c[i] << 5
		c[i-3] ^= c[i] >> 59
		c[i-4] ^= c[i] << 2
		c[i-3] ^= c[i] >> 62
		c[i-4] ^= c[i]
	}
	C := make([]byte, 32)
	for i := 0; i < 32; i++ {
		C[i] = byte(c[i>>3] >> (i & 0x07 << 3)) // truncate word to byte
	}
	return C
}

// NewCOtReceiver creates a `Receiver` instance, ready for use as the receiver in the KOS cOT protocol
// you must supply the output gotten by running an instance of seed OT as the _sender_ (note the reversal of roles)
func NewCOtReceiver(kappa uint, s uint, seedOTResults *simplest.SenderOutput, curve *curves.Curve) *Receiver {
	return &Receiver{
		Kappa:                     kappa,
		KappaBytes:                kappa >> 3,
		L:                         2*kappa + 2*s,
		COtBlockSizeBytes:         (2*kappa + 2*s) >> 3,
		OtWidth:                   2,
		s:                         s,
		kappaOT:                   kappa + s,
		lPrime:                    (2*kappa + 2*s) + (kappa + s), // length of pseudorandom seed expansion, used within cOT protocol
		cOtExtendedBlockSizeBytes: (2*kappa + 2*s) + (kappa+s)>>3,
		seedOtResults:             seedOTResults,
		curve:                     curve,
	}
}

// NewCOtSender creates a `Sender` instance, ready for use as the sender in the KOS cOT protocol.
// you must supply the output gotten by running an instance of seed OT as the _receiver_ (note the reversal of roles)
func NewCOtSender(kappa uint, s uint, seedOTResults *simplest.ReceiverOutput, curve *curves.Curve) *Sender {
	return &Sender{
		Kappa:                     kappa,
		KappaBytes:                kappa >> 3,
		L:                         2*kappa + 2*s,
		COtBlockSizeBytes:         (2*kappa + 2*s) >> 3,
		OtWidth:                   2,
		s:                         s,
		kappaOT:                   kappa + s,
		lPrime:                    (2*kappa + 2*s) + (kappa + s), // length of pseudorandom seed expansion, used within cOT protocol
		cOtExtendedBlockSizeBytes: (2*kappa + 2*s) + (kappa+s)>>3,
		seedOtResults:             seedOTResults,
		curve:                     curve,
	}
}

// Round1Output is Bob's first message to Alice during cOT extension;
// these outputs are described in step 4) of Protocol 9) https://eprint.iacr.org/2018/499.pdf
type Round1Output struct {
	U      [][]byte
	WPrime [simplest.DigestSize]byte
	VPrime [simplest.DigestSize]byte
}

// Round2Output this is Alice's response to Bob in cOT extension;
// the values `tau` are specified in Alice's step 6) of Protocol 9) https://eprint.iacr.org/2018/499.pdf
type Round2Output struct {
	Tau [][]curves.Scalar
}

// convertBitToBitmask converts a "bit"---i.e., a `byte` which is _assumed to be_ either 0 or 1---into a bitmask,
// namely, it outputs 0x00 if `bit == 0` and 0xFF if `bit == 1`.
func convertBitToBitmask(bit byte) byte {
	return ^(bit - 0x01)
}

// the below code takes as input a `kappa` by `lPrime` _boolean_ matrix, whose rows are actually "compacted" as bytes.
// so in actuality, it's a `kappa` by `lPrime >> 3 == cOtExtendedBlockSizeBytes` matrix of _bytes_.
// its output is the same boolean matrix, but transposed, so it has dimensions `lPrime` by `kappa`.
// but likewise we want to compact the output matrix as bytes, again _row-wise_.
// so the output matrix's dimensions are lPrime by `kappa >> 3 == KappaBytes`, as a _byte_ matrix.
// the technique is fairly straightforward, but involves some bitwise operations.
func transposeBooleanMatrix(input [][]byte) [][]byte {
	cotextendedblocksizebytes := len(input[0])
	lprime := cotextendedblocksizebytes << 3
	kappabytes := len(input) >> 3

	output := make([][]byte, lprime)

	for i := 0; i < lprime; i++ {
		output[i] = make([]byte, kappabytes)
	}

	for rowByte := 0; rowByte < kappabytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < cotextendedblocksizebytes; columnByte++ {
				for columnBitWithinByte := 0; columnBitWithinByte < 8; columnBitWithinByte++ {
					rowBit := rowByte<<3 + rowBitWithinByte
					columnBit := columnByte<<3 + columnBitWithinByte
					// the below code grabs the _bit_ at input[rowBit][columnBit], if input were a viewed as a boolean matrix.
					// in reality, it's packed into bytes, so instead we have to grab the `columnBitWithinByte`th bit within the appropriate byte.
					bitAtInputRowBitColumnBit := input[rowBit][columnByte] >> columnBitWithinByte & 0x01
					// now that we've grabbed the bit we care about, we need to write it into the appropriate place in the output matrix
					// the output matrix is also packed---but in the "opposite" way (the short dimension is packed, instead of the long one)
					// what we're going to do is take the _bit_ we got, and shift it by rowBitWithinByte.
					// this has the effect of preparing for us to write it into the appropriate place into the output matrix.
					shiftedBit := bitAtInputRowBitColumnBit << rowBitWithinByte
					output[columnBit][rowByte] |= shiftedBit
				}
			}
		}
	}
	return output
}

// Round1Initialize initializes the OT Extension. see page 17, steps 1), 2), 3) and 4) of Protocol 9 of the paper.
// The input `choice` vector is "packed" (i.e., the underlying abstract vector of `L` bits is represented as a `cOTBlockSizeBytes` bytes).
func (receiver *Receiver) Round1Initialize(uniqueSessionId [simplest.DigestSize]byte, choice []byte) (*Round1Output, error) {
	// salt the transcript with the OT-extension session ID
	receiver.uniqueSessionId = uniqueSessionId
	receiver.extendedPackedChoices = make([]byte, receiver.cOtExtendedBlockSizeBytes)

	// write the input choice vector into our local data. Since `otBatchSize` is the number of bits, we are working with
	// bytes, we first need to calculate how many bytes are needed to store that many bits.
	copy(receiver.extendedPackedChoices[0:receiver.COtBlockSizeBytes], choice[:])

	// Fill the rest of the extended choice vector with random values. These random values correspond to `gamma^{ext}`.
	if _, err := rand.Read(receiver.extendedPackedChoices[receiver.COtBlockSizeBytes:]); err != nil {
		return nil, errors.Wrap(err, "sampling random coins for gamma^{ext}")
	}

	v := [2][][]byte{} // kappa * L array of _bits_, in "dense" form. contains _both_ v_0 and v_1.
	for i := 0; i < 2; i++ {
		v[i] = make([][]byte, receiver.Kappa)
		for j := uint(0); j < receiver.Kappa; j++ {
			v[i][j] = make([]byte, receiver.cOtExtendedBlockSizeBytes)
		}
	}
	result := &Round1Output{}
	result.U = make([][]byte, receiver.Kappa)
	for i := uint(0); i < receiver.Kappa; i++ {
		result.U[i] = make([]byte, receiver.cOtExtendedBlockSizeBytes)
	}

	hash := sha3.New256() // basically this will contain a hash of the matrix U.
	for i := uint(0); i < receiver.Kappa; i++ {
		for j := 0; j < 2; j++ {
			shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
			if _, err := shake.Write(receiver.seedOtResults.OneTimePadEncryptionKeys[i][j][:]); err != nil {
				return nil, errors.Wrap(err, "writing seed OT into shake in cOT receiver round 1")
			}
			// this is the core pseudorandom expansion of the secret OT input seeds s_i^0 and s_i^1
			// see Extension, 2), in Protocol 9, page 17 of DKLs https://eprint.iacr.org/2018/499.pdf
			// use the uniqueSessionId as the "domain separator", and the _secret_ seed rho as the input!
			if _, err := shake.Read(v[j][i][:]); err != nil {
				return nil, errors.Wrap(err, "reading from shake to compute v^j in cOT receiver round 1")
			}
		}

		for j := uint(0); j < receiver.cOtExtendedBlockSizeBytes; j++ {
			result.U[i][j] = v[0][i][j] ^ v[1][i][j] ^ receiver.extendedPackedChoices[j]
			// U := v_i^0 ^ v_i^1 ^ w. note: in step 4) of Prot. 9, i think `w` should be bolded?
		}
		if _, err := hash.Write(result.U[i][:]); err != nil {
			return nil, err
		}
	}
	receiver.psi = transposeBooleanMatrix(v[0])
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	for j := uint(0); j < receiver.lPrime; j++ {
		hash = sha3.New256()
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := hash.Write(jBytes[:]); err != nil { // write j into shake
			return nil, errors.Wrap(err, "writing nonce into hash while computing chiJ in cOT receiver round 1")
		}
		if _, err := hash.Write(digest); err != nil {
			return nil, errors.Wrap(err, "writing input digest into hash while computing chiJ in cOT receiver round 1")
		}
		chiJ := hash.Sum(nil)
		wJ := convertBitToBitmask(simplest.ExtractBitFromByteVector(receiver.extendedPackedChoices[:], int(j))) // extract j^th bit from vector of bytes w.
		psiJTimesChiJ := binaryFieldMul(receiver.psi[j][:], chiJ)
		for k := uint(0); k < simplest.DigestSize; k++ {
			result.WPrime[k] ^= wJ & chiJ[k]
			result.VPrime[k] ^= psiJTimesChiJ[k]
		}
	}
	return result, nil
}

// Round2Transfer computes the OT sender ("Alice")'s part of cOT; this includes steps 2) 5) and 6) of Protocol 9
// `input` is the sender's main vector of inputs alpha_j; these are the things tA_j and tB_j will add to if w_j == 1.
// `message` contains the message the receiver ("Bob") sent us. this itself contains Bob's values WPrime, VPrime, and U
// the output is just the values `Tau` we send back to Bob.
// as a side effect of this function, our (i.e., the sender's) outputs tA_j from the cOT will be populated.
func (sender *Sender) Round2Transfer(uniqueSessionId [simplest.DigestSize]byte, input [][]curves.Scalar, round1Output *Round1Output) (*Round2Output, error) {
	z := make([][]byte, sender.Kappa)
	for i := uint(0); i < sender.Kappa; i++ {
		z[i] = make([]byte, sender.cOtExtendedBlockSizeBytes)
	}
	hash := sha3.New256() // basically this will contain a hash of the matrix U.

	for i := uint(0); i < sender.Kappa; i++ {
		v := make([]byte, sender.cOtExtendedBlockSizeBytes) // will contain alice's expanded PRG output for the row i, namely v_i^{\Nabla_i}.
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		if _, err := shake.Write(sender.seedOtResults.OneTimePadDecryptionKey[i][:]); err != nil {
			return nil, errors.Wrap(err, "sender writing seed OT decryption key into shake in sender round 2 transfer")
		}
		if _, err := shake.Read(v); err != nil {
			return nil, errors.Wrap(err, "reading from shake into row `v` in sender round 2 transfer")
		}
		// use the idExt as the domain separator, and the _secret_ seed rho as the input!
		mask := convertBitToBitmask(byte(sender.seedOtResults.RandomChoiceBits[i]))
		for j := uint(0); j < sender.cOtExtendedBlockSizeBytes; j++ {
			z[i][j] = v[j] ^ mask&round1Output.U[i][j]
		}
		if _, err := hash.Write(round1Output.U[i][:]); err != nil {
			return nil, errors.Wrap(err, "writing matrix U to hash in cOT sender round 2 transfer")
		}
	}
	zeta := transposeBooleanMatrix(z)
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	zPrime := [simplest.DigestSize]byte{}
	for j := uint(0); j < sender.lPrime; j++ {
		hash = sha3.New256()
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := hash.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into hash while computing chiJ in cOT sender round 2 transfer")
		}
		if _, err := hash.Write(digest); err != nil {
			return nil, errors.Wrap(err, "writing input digest into hash while computing chiJ in cOT sender round 2 transfer")
		}
		chiJ := hash.Sum(nil)
		zetaJTimesChiJ := binaryFieldMul(zeta[j][:], chiJ)
		for k := uint(0); k < simplest.DigestSize; k++ {
			zPrime[k] ^= zetaJTimesChiJ[k]
		}
	}
	rhs := [simplest.DigestSize]byte{}
	nablaTimesWPrime := binaryFieldMul(sender.seedOtResults.PackedRandomChoiceBits, round1Output.WPrime[:])
	for i := uint(0); i < simplest.DigestSize; i++ {
		rhs[i] = round1Output.VPrime[i] ^ nablaTimesWPrime[i]
	}
	if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
		return nil, fmt.Errorf("cOT receiver's consistency check failed; this may be an attempted attack; do NOT re-run the protocol")
	}
	result := &Round2Output{}
	result.Tau = make([][]curves.Scalar, sender.L)
	sender.OutputAdditiveShares = make([][]curves.Scalar, sender.L)
	for j := uint(0); j < sender.L; j++ {
		sender.OutputAdditiveShares[j] = make([]curves.Scalar, sender.OtWidth)
		result.Tau[j] = make([]curves.Scalar, sender.OtWidth)
		column := make([]byte, sender.OtWidth*simplest.DigestSize)
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into shake while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		if _, err := shake.Write(zeta[j][:]); err != nil {
			return nil, errors.Wrap(err, "writing input zeta_j into shake while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return nil, errors.Wrap(err, "reading shake into column while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		var err error
		for k := uint(0); k < sender.OtWidth; k++ {
			sender.OutputAdditiveShares[j][k], err = sender.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return nil, errors.Wrap(err, "OutputAdditiveShares scalar from bytes")
			}
		}
		for i := uint(0); i < sender.KappaBytes; i++ {
			zeta[j][i] ^= sender.seedOtResults.PackedRandomChoiceBits[i] // note: overwrites zeta_j. just using it as a place to store
		}
		column = make([]byte, sender.OtWidth*simplest.DigestSize)
		shake = sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into shake while computing tau in cOT sender round 2 transfer")
		}
		if _, err := shake.Write(zeta[j][:]); err != nil {
			return nil, errors.Wrap(err, "writing input zeta_j into shake while computing tau in cOT sender round 2 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return nil, errors.Wrap(err, "reading shake into column while computing tau in cOT sender round 2 transfer")
		}
		for k := uint(0); k < sender.OtWidth; k++ {
			result.Tau[j][k], err = sender.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return nil, errors.Wrap(err, "scalar Tau from bytes")
			}
			result.Tau[j][k] = result.Tau[j][k].Sub(sender.OutputAdditiveShares[j][k])
			result.Tau[j][k] = result.Tau[j][k].Add(input[j][k])
		}
	}
	return result, nil
}

// Round3Transfer does the receiver (Bob)'s step 7) of Protocol 9, namely the computation of the outputs tB.
func (receiver *Receiver) Round3Transfer(round2Output *Round2Output) error {
	receiver.OutputAdditiveShares = make([][]curves.Scalar, receiver.L)
	for j := uint(0); j < receiver.L; j++ {
		receiver.OutputAdditiveShares[j] = make([]curves.Scalar, receiver.OtWidth)
		column := make([]byte, receiver.OtWidth*simplest.DigestSize)
		shake := sha3.NewCShake256(receiver.uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return errors.Wrap(err, "writing nonce into shake while computing tB in cOT receiver round 3 transfer")
		}
		if _, err := shake.Write(receiver.psi[j][:]); err != nil {
			return errors.Wrap(err, "writing input zeta_j into shake while computing tB in cOT receiver round 3 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return errors.Wrap(err, "reading shake into column while computing tB in cOT receiver round 3 transfer")
		}
		bit := int(simplest.ExtractBitFromByteVector(receiver.extendedPackedChoices[:], int(j)))
		var err error
		for k := uint(0); k < receiver.OtWidth; k++ {
			receiver.OutputAdditiveShares[j][k], err = receiver.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return errors.Wrap(err, "scalar output additive shares from bytes")
			}
			receiver.OutputAdditiveShares[j][k] = receiver.OutputAdditiveShares[j][k].Neg()
			wj0 := receiver.OutputAdditiveShares[j][k].Bytes()
			wj1 := receiver.OutputAdditiveShares[j][k].Add(round2Output.Tau[j][k]).Bytes()
			subtle.ConstantTimeCopy(bit, wj0, wj1)
			if receiver.OutputAdditiveShares[j][k], err = receiver.curve.Scalar.SetBytes(wj0); err != nil {
				return errors.Wrap(err, "scalar output additive shares from bytes")
			}
		}
	}
	return nil
}
