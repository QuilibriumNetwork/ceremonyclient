//
// Copyright (c) 2019 harmony-one
// Copyright (c) 2023 Quilibrium, Inc.
//
// SPDX-License-Identifier: MIT
//

package vdf

// VDF is the struct holding necessary state for a hash chain delay function.
// Differs from harmony implementation in that difficulty is carried through as
// an unsigned int, because we can't travel backwards in time (yet ;) )
type VDF struct {
	difficulty uint32
	input      [32]byte
	output     [516]byte
	outputChan chan [516]byte
	finished   bool
}

// size of long integers in quadratic function group
const sizeInBits = 2048

// New create a new instance of VDF.
func New(difficulty uint32, input [32]byte) *VDF {
	return &VDF{
		difficulty: difficulty,
		input:      input,
		outputChan: make(chan [516]byte),
	}
}

// GetOutputChannel returns the vdf output channel.
// VDF output consists of 258 bytes of serialized Y and  258 bytes of serialized Proof
func (vdf *VDF) GetOutputChannel() chan [516]byte {
	return vdf.outputChan
}

// Execute runs the VDF until it's finished and put the result into output channel.
// currently on i7-6700K, it takes about 14 seconds when iteration is set to 10000
func (vdf *VDF) Execute() {
	vdf.finished = false

	yBuf, proofBuf := GenerateVDF(vdf.input[:], vdf.difficulty, sizeInBits)

	copy(vdf.output[:], yBuf)
	copy(vdf.output[258:], proofBuf)

	go func() {
		vdf.outputChan <- vdf.output
	}()

	vdf.finished = true
}

func (vdf *VDF) ExecuteIteration(x_blob []byte) {
	vdf.finished = false

	yBuf, proofBuf := GenerateVDFIteration(vdf.input[:], x_blob, vdf.difficulty, sizeInBits)

	copy(vdf.output[:], yBuf)
	copy(vdf.output[258:], proofBuf)

	go func() {
		vdf.outputChan <- vdf.output
	}()

	vdf.finished = true
}

// Verify runs the verification of generated proof
// currently on i7-6700K, verification takes about 350 ms
func (vdf *VDF) Verify(proof [516]byte) bool {
	return VerifyVDF(vdf.input[:], proof[:], vdf.difficulty, sizeInBits)
}

func (vdf *VDF) VerifyIteration(x_blob [258]byte, proof [516]byte, iterations uint32) bool {
	return VerifyVDFIteration(vdf.input[:], x_blob[:], proof[:], vdf.difficulty, sizeInBits)
}

// IsFinished returns whether the vdf execution is finished or not.
func (vdf *VDF) IsFinished() bool {
	return vdf.finished
}

// GetOutput returns the vdf output, which can be bytes of 0s is the vdf is not finished.
func (vdf *VDF) GetOutput() [516]byte {
	return vdf.output
}
