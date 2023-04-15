package feldman

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"source.quilibrium.com/quilibrium/ceremonyclient/ec/bls48581"
)

// This will not be used in the initial ceremony, but will be used in a end of ceremony event
type FeldmanECP struct {
	threshold                   int
	total                       int
	id                          int
	fragsForCounterparties      map[int][]byte
	fragsFromCounterparties     map[int]*bls48581.BIG
	zkpok                       *bls48581.BIG
	secret                      *bls48581.BIG
	scalar                      *bls48581.BIG
	publicKey                   *bls48581.ECP
	point                       *bls48581.ECP
	randomCommitmentPoint       *bls48581.ECP
	round                       FeldmanRound
	zkcommitsFromCounterparties map[int][]byte
	pointsFromCounterparties    map[int]*bls48581.ECP
}

type FeldmanReveal struct {
	Point                 []byte
	RandomCommitmentPoint []byte
	ZKPoK                 []byte
}

type FeldmanECP8 struct {
	threshold                   int
	total                       int
	id                          int
	fragsForCounterparties      map[int][]byte
	fragsFromCounterparties     map[int]*bls48581.BIG
	zkpok                       *bls48581.BIG
	secret                      *bls48581.BIG
	scalar                      *bls48581.BIG
	publicKey                   *bls48581.ECP8
	point                       *bls48581.ECP8
	randomCommitmentPoint       *bls48581.ECP8
	round                       FeldmanRound
	zkcommitsFromCounterparties map[int][]byte
	pointsFromCounterparties    map[int]*bls48581.ECP8
}

type FeldmanRound int

const (
	FELDMAN_ROUND_UNINITIALIZED = FeldmanRound(0)
	FELDMAN_ROUND_INITIALIZED   = FeldmanRound(1)
	FELDMAN_ROUND_COMMITTED     = FeldmanRound(2)
	FELDMAN_ROUND_REVEALED      = FeldmanRound(3)
	FELDMAN_ROUND_RECONSTRUCTED = FeldmanRound(4)
)

func NewFeldmanECP(threshold, total, id int, secret *bls48581.BIG) (*FeldmanECP, error) {
	return &FeldmanECP{
		threshold:                   threshold,
		total:                       total,
		id:                          id,
		fragsForCounterparties:      make(map[int][]byte),
		fragsFromCounterparties:     make(map[int]*bls48581.BIG),
		zkpok:                       nil,
		secret:                      secret,
		scalar:                      nil,
		publicKey:                   bls48581.ECP_generator(),
		point:                       bls48581.ECP_generator(),
		round:                       FELDMAN_ROUND_UNINITIALIZED,
		zkcommitsFromCounterparties: make(map[int][]byte),
		pointsFromCounterparties:    make(map[int]*bls48581.ECP),
	}, nil
}

func NewFeldmanECP8(threshold, total, id int, secret *bls48581.BIG) (*FeldmanECP8, error) {
	return &FeldmanECP8{
		threshold:                   threshold,
		total:                       total,
		id:                          id,
		fragsForCounterparties:      make(map[int][]byte),
		fragsFromCounterparties:     make(map[int]*bls48581.BIG),
		zkpok:                       nil,
		secret:                      secret,
		scalar:                      nil,
		publicKey:                   bls48581.ECP8_generator(),
		point:                       bls48581.ECP8_generator(),
		round:                       FELDMAN_ROUND_UNINITIALIZED,
		zkcommitsFromCounterparties: make(map[int][]byte),
		pointsFromCounterparties:    make(map[int]*bls48581.ECP8),
	}, nil
}

func (f *FeldmanECP) SamplePolynomial() {
	coeffs := append([]*bls48581.BIG{}, f.secret)

	for i := 0; i < f.threshold-1; i++ {
		secretBytes := make([]byte, int(bls48581.MODBYTES))
		rand.Read(secretBytes)
		secret := bls48581.FromBytes(secretBytes)
		coeffs = append(coeffs, secret)
	}

	for i := 1; i <= f.total; i++ {
		result := coeffs[len(coeffs)-1]

		for j := len(coeffs) - 2; j >= 0; j-- {
			result = bls48581.Modadd(
				coeffs[j],
				bls48581.Modmul(
					result,
					bls48581.NewBIGint(i),
					bls48581.NewBIGints(bls48581.CURVE_Order),
				),
				bls48581.NewBIGints(bls48581.CURVE_Order),
			)
		}

		if i == f.id {
			f.scalar = result
		} else {
			fragBytes := make([]byte, int(bls48581.MODBYTES))
			result.ToBytes(fragBytes)
			f.fragsForCounterparties[i] = fragBytes
		}
	}

	f.round = FELDMAN_ROUND_INITIALIZED
}

func (f *FeldmanECP) Scalar() *bls48581.BIG {
	return f.scalar
}

func (f *FeldmanECP) GetPolyFrags() map[int][]byte {
	return f.fragsForCounterparties
}

func (f *FeldmanECP) SetPolyFragForParty(id int, frag []byte) []byte {
	f.fragsFromCounterparties[id] = bls48581.FromBytes(frag)

	if len(f.fragsFromCounterparties) == f.total-1 {
		for _, v := range f.fragsFromCounterparties {
			f.scalar = bls48581.Modadd(f.scalar, v, bls48581.NewBIGints(bls48581.CURVE_Order))
		}

		f.point = f.point.Mul(f.scalar)

		randCommitmentBytes := make([]byte, int(bls48581.MODBYTES))
		rand.Read(randCommitmentBytes)
		randCommitment := bls48581.FromBytes(randCommitmentBytes)
		f.randomCommitmentPoint = f.publicKey.Mul(randCommitment)

		publicPointBytes := make([]byte, bls48581.MODBYTES+1)
		randCommitmentPointBytes := make([]byte, bls48581.MODBYTES+1)
		f.point.ToBytes(publicPointBytes, true)
		f.randomCommitmentPoint.ToBytes(randCommitmentPointBytes, true)

		challenge := sha256.Sum256(append(append([]byte{}, publicPointBytes...), randCommitmentPointBytes...))
		challengeBig := bls48581.FromBytes(challenge[:])
		challengeBig.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))

		f.zkpok = bls48581.Modadd(
			bls48581.Modmul(
				f.scalar,
				challengeBig,
				bls48581.NewBIGints(bls48581.CURVE_Order),
			),
			randCommitment,
			bls48581.NewBIGints(bls48581.CURVE_Order),
		)

		zkpokBytes := make([]byte, int(bls48581.MODBYTES))
		f.zkpok.ToBytes(zkpokBytes)
		zkcommit := sha256.Sum256(append(append([]byte{}, randCommitmentPointBytes...), zkpokBytes...))

		f.round = FELDMAN_ROUND_COMMITTED
		return zkcommit[:]
	}

	return []byte{}
}

func (f *FeldmanECP) ReceiveCommitments(id int, zkcommit []byte) *FeldmanReveal {
	f.zkcommitsFromCounterparties[id] = zkcommit

	if len(f.zkcommitsFromCounterparties) == f.total-1 {
		publicPointBytes := make([]byte, bls48581.MODBYTES+1)
		randCommitmentPointBytes := make([]byte, bls48581.MODBYTES+1)
		f.point.ToBytes(publicPointBytes, true)
		f.randomCommitmentPoint.ToBytes(randCommitmentPointBytes, true)
		f.round = FELDMAN_ROUND_REVEALED
		zkpokBytes := make([]byte, int(bls48581.MODBYTES))
		f.zkpok.ToBytes(zkpokBytes)

		return &FeldmanReveal{
			Point:                 publicPointBytes,
			RandomCommitmentPoint: randCommitmentPointBytes,
			ZKPoK:                 zkpokBytes,
		}
	}

	return nil
}

func (f *FeldmanECP) Recombine(id int, reveal *FeldmanReveal) {
	counterpartyPoint := bls48581.ECP_fromBytes(reveal.Point)
	if counterpartyPoint.Equals(bls48581.ECP_generator()) {
		fmt.Printf("invalid point from %d", id)
		return
	}

	counterpartyRandomCommitmentPoint := bls48581.ECP_fromBytes(reveal.RandomCommitmentPoint)
	if counterpartyRandomCommitmentPoint.Equals(bls48581.ECP_generator()) {
		fmt.Printf("invalid commitment point from %d", id)
		return
	}

	counterpartyZKPoK := bls48581.FromBytes(reveal.ZKPoK)
	counterpartyZKCommit := f.zkcommitsFromCounterparties[id]

	challenge := sha256.Sum256(append(append([]byte{}, reveal.Point...), reveal.RandomCommitmentPoint...))
	challengeBig := bls48581.FromBytes(challenge[:])
	challengeBig.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))

	proof := f.publicKey.Mul(counterpartyZKPoK)
	counterpartyRandomCommitmentPoint.Add(counterpartyPoint.Mul(challengeBig))

	if !proof.Equals(counterpartyRandomCommitmentPoint) {
		fmt.Printf("invalid proof from %d", id)
		return
	}

	verifier := sha256.Sum256(append(append([]byte{}, reveal.RandomCommitmentPoint...), reveal.ZKPoK...))
	if !bytes.Equal(counterpartyZKCommit, verifier[:]) {
		fmt.Printf("%d changed zkpok after commit", id)
		return
	}

	f.pointsFromCounterparties[id] = counterpartyPoint

	if len(f.pointsFromCounterparties) == f.total-1 {
		f.pointsFromCounterparties[f.id] = f.point

		for i := 1; i <= f.total-f.threshold; i++ {
			reconstructedSum := bls48581.ECP_generator()

			for j := i; j <= f.threshold+i; j++ {
				coefficientNumerator := bls48581.NewBIGint(1)
				coefficientDenominator := bls48581.NewBIGint(1)

				for k := i; k <= f.threshold+i; k++ {
					if j != k {
						k := bls48581.NewBIGint(k)

						coefficientNumerator = bls48581.Modmul(
							coefficientNumerator,
							k,
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
						kj := bls48581.Modadd(
							k,
							bls48581.NewBIGints(bls48581.CURVE_Order).Minus(bls48581.NewBIGint(j)),
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
						coefficientDenominator = bls48581.Modmul(
							coefficientDenominator,
							kj,
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
					}
				}

				coefficientDenominator.Invmodp(bls48581.NewBIGints(bls48581.CURVE_Order))

				reconstructedFragment := f.pointsFromCounterparties[j].Mul(
					bls48581.Modmul(
						coefficientNumerator,
						coefficientDenominator,
						bls48581.NewBIGints(bls48581.CURVE_Order),
					),
				)

				if reconstructedSum.Equals(bls48581.ECP_generator()) {
					reconstructedSum = reconstructedFragment
				} else {
					reconstructedSum.Add(reconstructedFragment)
				}
			}

			if f.publicKey.Equals(bls48581.ECP_generator()) {
				f.publicKey = reconstructedSum
			} else if !f.publicKey.Equals(reconstructedSum) {
				fmt.Println("key mismatch")
				fmt.Println(f.publicKey.ToString())
				fmt.Println(reconstructedSum.ToString())
				return
			}
		}
		f.round = FELDMAN_ROUND_RECONSTRUCTED
	}
}

func (f *FeldmanECP) PublicKey() *bls48581.ECP {
	key := bls48581.NewECP()
	key.Copy(f.publicKey)
	return key
}

func (f *FeldmanECP) PublicKeyBytes() []byte {
	publicKeyBytes := make([]byte, bls48581.MODBYTES+1)
	f.publicKey.ToBytes(publicKeyBytes, true)
	return publicKeyBytes
}

func (f *FeldmanECP8) SamplePolynomial() {
	coeffs := append([]*bls48581.BIG{}, f.secret)

	for i := 0; i < f.threshold-1; i++ {
		secretBytes := make([]byte, int(bls48581.MODBYTES))
		rand.Read(secretBytes)
		secret := bls48581.FromBytes(secretBytes)
		coeffs = append(coeffs, secret)
	}

	for i := 1; i <= f.total; i++ {
		result := coeffs[len(coeffs)-1]

		for j := len(coeffs) - 2; j >= 0; j-- {
			result = bls48581.Modadd(
				coeffs[j],
				bls48581.Modmul(
					result,
					bls48581.NewBIGint(i),
					bls48581.NewBIGints(bls48581.CURVE_Order),
				),
				bls48581.NewBIGints(bls48581.CURVE_Order),
			)
		}

		if i == f.id {
			f.scalar = result
		} else {
			fragBytes := make([]byte, int(bls48581.MODBYTES))
			result.ToBytes(fragBytes)
			f.fragsForCounterparties[i] = fragBytes
		}
	}

	f.round = FELDMAN_ROUND_INITIALIZED
}

func (f *FeldmanECP8) GetPolyFrags() map[int][]byte {
	return f.fragsForCounterparties
}

func (f *FeldmanECP8) SetPolyFragForParty(id int, frag []byte) []byte {
	f.fragsFromCounterparties[id] = bls48581.FromBytes(frag)

	if len(f.fragsFromCounterparties) == f.total-1 {
		for _, v := range f.fragsFromCounterparties {
			f.scalar = bls48581.Modadd(f.scalar, v, bls48581.NewBIGints(bls48581.CURVE_Order))
		}

		f.point = f.point.Mul(f.scalar)

		randCommitmentBytes := make([]byte, int(bls48581.MODBYTES))
		rand.Read(randCommitmentBytes)
		randCommitment := bls48581.FromBytes(randCommitmentBytes)
		f.randomCommitmentPoint = f.publicKey.Mul(randCommitment)

		publicPointBytes := make([]byte, bls48581.MODBYTES*8+1)
		randCommitmentPointBytes := make([]byte, bls48581.MODBYTES*8+1)
		f.point.ToBytes(publicPointBytes, true)
		f.randomCommitmentPoint.ToBytes(randCommitmentPointBytes, true)

		challenge := sha256.Sum256(append(append([]byte{}, publicPointBytes...), randCommitmentPointBytes...))
		challengeBig := bls48581.FromBytes(challenge[:])
		challengeBig.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))

		f.zkpok = bls48581.Modadd(
			bls48581.Modmul(
				f.scalar,
				challengeBig,
				bls48581.NewBIGints(bls48581.CURVE_Order),
			),
			randCommitment,
			bls48581.NewBIGints(bls48581.CURVE_Order),
		)

		zkpokBytes := make([]byte, int(bls48581.MODBYTES))
		f.zkpok.ToBytes(zkpokBytes)
		zkcommit := sha256.Sum256(append(append([]byte{}, randCommitmentPointBytes...), zkpokBytes...))

		f.round = FELDMAN_ROUND_COMMITTED
		return zkcommit[:]
	}

	return []byte{}
}

func (f *FeldmanECP8) Scalar() *bls48581.BIG {
	return f.scalar
}

func (f *FeldmanECP8) ReceiveCommitments(id int, zkcommit []byte) *FeldmanReveal {
	f.zkcommitsFromCounterparties[id] = zkcommit

	if len(f.zkcommitsFromCounterparties) == f.total-1 {
		publicPointBytes := make([]byte, bls48581.MODBYTES*8+1)
		randCommitmentPointBytes := make([]byte, bls48581.MODBYTES*8+1)
		f.point.ToBytes(publicPointBytes, true)
		f.randomCommitmentPoint.ToBytes(randCommitmentPointBytes, true)
		f.round = FELDMAN_ROUND_REVEALED
		zkpokBytes := make([]byte, int(bls48581.MODBYTES))
		f.zkpok.ToBytes(zkpokBytes)

		return &FeldmanReveal{
			Point:                 publicPointBytes,
			RandomCommitmentPoint: randCommitmentPointBytes,
			ZKPoK:                 zkpokBytes,
		}
	}

	return nil
}

func (f *FeldmanECP8) Recombine(id int, reveal *FeldmanReveal) {
	counterpartyPoint := bls48581.ECP8_fromBytes(reveal.Point)
	if counterpartyPoint.Equals(bls48581.ECP8_generator()) {
		fmt.Printf("invalid point from %d", id)
		return
	}

	counterpartyRandomCommitmentPoint := bls48581.ECP8_fromBytes(reveal.RandomCommitmentPoint)
	if counterpartyRandomCommitmentPoint.Equals(bls48581.ECP8_generator()) {
		fmt.Printf("invalid commitment point from %d", id)
		return
	}

	counterpartyZKPoK := bls48581.FromBytes(reveal.ZKPoK)
	counterpartyZKCommit := f.zkcommitsFromCounterparties[id]

	challenge := sha256.Sum256(append(append([]byte{}, reveal.Point...), reveal.RandomCommitmentPoint...))
	challengeBig := bls48581.FromBytes(challenge[:])
	challengeBig.Mod(bls48581.NewBIGints(bls48581.CURVE_Order))

	proof := f.publicKey.Mul(counterpartyZKPoK)
	counterpartyRandomCommitmentPoint.Add(counterpartyPoint.Mul(challengeBig))

	if !proof.Equals(counterpartyRandomCommitmentPoint) {
		fmt.Printf("invalid proof from %d", id)
		return
	}

	verifier := sha256.Sum256(append(append([]byte{}, reveal.RandomCommitmentPoint...), reveal.ZKPoK...))
	if !bytes.Equal(counterpartyZKCommit, verifier[:]) {
		fmt.Printf("%d changed zkpok after commit", id)
		return
	}

	f.pointsFromCounterparties[id] = counterpartyPoint

	if len(f.pointsFromCounterparties) == f.total-1 {
		f.pointsFromCounterparties[f.id] = f.point
		for i := 1; i <= f.total-f.threshold; i++ {
			reconstructedSum := bls48581.ECP8_generator()

			for j := i; j <= f.threshold+i; j++ {
				coefficientNumerator := bls48581.NewBIGint(1)
				coefficientDenominator := bls48581.NewBIGint(1)

				for k := i; k <= f.threshold+i; k++ {
					if j != k {
						k := bls48581.NewBIGint(k)

						coefficientNumerator = bls48581.Modmul(
							coefficientNumerator,
							k,
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
						kj := bls48581.Modadd(
							k,
							bls48581.NewBIGints(bls48581.CURVE_Order).Minus(bls48581.NewBIGint(j)),
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
						coefficientDenominator = bls48581.Modmul(
							coefficientDenominator,
							kj,
							bls48581.NewBIGints(bls48581.CURVE_Order),
						)
					}
				}

				coefficientDenominator.Invmodp(bls48581.NewBIGints(bls48581.CURVE_Order))

				reconstructedFragment := f.pointsFromCounterparties[j].Mul(
					bls48581.Modmul(
						coefficientNumerator,
						coefficientDenominator,
						bls48581.NewBIGints(bls48581.CURVE_Order),
					),
				)

				if reconstructedSum.Equals(bls48581.ECP8_generator()) {
					reconstructedSum = reconstructedFragment
				} else {
					reconstructedSum.Add(reconstructedFragment)
				}
			}

			if f.publicKey.Equals(bls48581.ECP8_generator()) {
				f.publicKey = reconstructedSum
			} else if !f.publicKey.Equals(reconstructedSum) {
				fmt.Println("key mismatch")
				fmt.Println(f.publicKey.ToString())
				fmt.Println(reconstructedSum.ToString())
				return
			}
		}
		f.round = FELDMAN_ROUND_RECONSTRUCTED
	}
}

func (f *FeldmanECP8) PublicKey() *bls48581.ECP8 {
	key := bls48581.NewECP8()
	key.Copy(f.publicKey)
	return key
}

func (f *FeldmanECP8) PublicKeyBytes() []byte {
	publicKeyBytes := make([]byte, bls48581.MODBYTES*8+1)
	f.publicKey.ToBytes(publicKeyBytes, true)
	return publicKeyBytes
}
