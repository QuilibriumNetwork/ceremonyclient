package kzg

import (
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

func recurseFFT(
	values []curves.PairingScalar,
	offset uint64,
	stride uint64,
	rootsStride uint64,
	out []curves.PairingScalar,
	fftWidth uint64,
	inverse bool,
) {
	roots := RootsOfUnityBLS48581
	if inverse {
		roots = ReverseRootsOfUnityBLS48581
	}

	if len(out) <= 16 {
		l := uint64(len(out))
		for i := uint64(0); i < l; i++ {
			last := values[offset].Mul(roots[fftWidth][0])

			for j := uint64(1); j < l; j++ {
				last = last.Add(values[offset+j*stride].Mul(
					roots[fftWidth][((i*j)%l)*rootsStride],
				))
			}
			out[i] = last.(curves.PairingScalar)
		}
		return
	}

	half := uint64(len(out)) >> 1
	// slide to the left
	recurseFFT(
		values,
		offset,
		stride<<1,
		rootsStride<<1,
		out[:half],
		fftWidth,
		inverse,
	)

	// slide to the right
	recurseFFT(
		values,
		offset+stride,
		stride<<1,
		rootsStride<<1,
		out[half:],
		fftWidth,
		inverse,
	)

	// cha cha now, y'all
	for i := uint64(0); i < half; i++ {
		mul := out[i+half].Mul(
			roots[fftWidth][i*rootsStride],
		).(curves.PairingScalar)
		mulAdd := out[i].Add(mul).(curves.PairingScalar)
		out[i+half] = out[i].Sub(mul).(curves.PairingScalar)
		out[i] = mulAdd
	}
}

func FFT(
	values []curves.PairingScalar,
	curve curves.PairingCurve,
	fftWidth uint64,
	inverse bool,
) ([]curves.PairingScalar, error) {
	width := uint64(len(values))
	if width > fftWidth {
		return nil, errors.New("invalid width of values")
	}

	if width&(width-1) != 0 {
		width = nearestPowerOfTwo(width)
	}

	// We make a copy so we can mutate it during the work.
	workingValues := make([]curves.PairingScalar, width)
	for i := 0; i < len(values); i++ {
		workingValue := values[i].Clone()
		workingValues[i] = workingValue.(curves.PairingScalar)
	}
	for i := uint64(len(values)); i < width; i++ {
		workingValue, err := curve.NewScalar().SetBigInt(
			big.NewInt(0),
		)
		if err != nil {
			return nil, errors.Wrap(err, "invalid scalar")
		}
		workingValues[i] = workingValue.(curves.PairingScalar)
	}

	out := make([]curves.PairingScalar, width)
	stride := fftWidth / width

	for i := 0; i < len(out); i++ {
		out[i] = curve.NewScalar()
	}

	if inverse {
		invLen, err := curve.NewScalar().SetBigInt(big.NewInt((int64(width))))
		if err != nil {
			return nil, errors.Wrap(err, "invalid int")
		}

		inv, err := invLen.Invert()
		if err != nil {
			return nil, errors.Wrap(err, "could not invert")
		}

		invLen = inv.(curves.PairingScalar)

		recurseFFT(workingValues, 0, 1, stride, out, fftWidth, inverse)
		for i := 0; i < len(out); i++ {
			out[i] = out[i].Mul(invLen).(curves.PairingScalar)
		}

		return out, nil
	} else {
		recurseFFT(workingValues, 0, 1, stride, out, fftWidth, inverse)
		return out, nil
	}
}

func recurseFFTG1(
	values []curves.PairingPoint,
	offset uint64,
	stride uint64,
	rootsStride uint64,
	out []curves.PairingPoint,
	fftWidth uint64,
	inverse bool,
) {
	roots := RootsOfUnityBLS48581
	if inverse {
		roots = ReverseRootsOfUnityBLS48581
	}

	if len(out) <= 16 {
		l := uint64(len(out))
		for i := uint64(0); i < l; i++ {
			last := values[offset].Mul(roots[fftWidth][0])

			for j := uint64(1); j < l; j++ {
				last = last.Add(values[offset+j*stride].Mul(
					roots[fftWidth][((i*j)%l)*rootsStride],
				))
			}

			out[i] = last.(curves.PairingPoint)
		}
		return
	}

	half := uint64(len(out)) >> 1
	// slide to the left
	recurseFFTG1(
		values,
		offset,
		stride<<1,
		rootsStride<<1,
		out[:half],
		fftWidth,
		inverse,
	)

	// slide to the right
	recurseFFTG1(
		values,
		offset+stride,
		stride<<1,
		rootsStride<<1,
		out[half:],
		fftWidth,
		inverse,
	)

	// cha cha now, y'all
	for i := uint64(0); i < half; i++ {
		mul := out[i+half].Mul(roots[fftWidth][i*rootsStride]).(curves.PairingPoint)
		mulAdd := out[i].Add(mul).(curves.PairingPoint)
		out[i+half] = out[i].Sub(mul).(curves.PairingPoint)
		out[i] = mulAdd
	}
}

func FFTG1(
	values []curves.PairingPoint,
	curve curves.PairingCurve,
	fftWidth uint64,
	inverse bool,
) ([]curves.PairingPoint, error) {
	width := uint64(len(values))
	if width > fftWidth {
		return nil, errors.New("invalid width of values")
	}

	if width&(width-1) != 0 {
		width = nearestPowerOfTwo(width)
	}

	workingValues := make([]curves.PairingPoint, width)
	for i := 0; i < len(values); i++ {
		workingValue, err := curve.NewG1GeneratorPoint().FromAffineCompressed(
			values[i].ToAffineCompressed(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "invalid point")
		}
		workingValues[i] = workingValue.(curves.PairingPoint)
	}
	for i := uint64(len(values)); i < width; i++ {
		workingValues[i] = curve.NewG1IdentityPoint()
	}

	out := make([]curves.PairingPoint, width)
	stride := fftWidth / width

	for i := 0; i < len(out); i++ {
		out[i] = curve.NewG1IdentityPoint()
	}

	if inverse {
		invLen, err := curve.NewScalar().SetBigInt(big.NewInt((int64(width))))
		if err != nil {
			return nil, errors.Wrap(err, "invalid int")
		}

		inv, err := invLen.Invert()
		if err != nil {
			return nil, errors.Wrap(err, "could not invert")
		}

		invLen = inv.(curves.PairingScalar)

		recurseFFTG1(workingValues, 0, 1, stride, out, fftWidth, inverse)
		for i := 0; i < len(out); i++ {
			out[i] = out[i].Mul(invLen).(curves.PairingPoint)
		}

		return out, nil
	} else {
		recurseFFTG1(workingValues, 0, 1, stride, out, fftWidth, inverse)
		return out, nil
	}
}

func nearestPowerOfTwo(number uint64) uint64 {
	power := uint64(1)
	for number > power {
		power = power << 1
	}

	return power
}
