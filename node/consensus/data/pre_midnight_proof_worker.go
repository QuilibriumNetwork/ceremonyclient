package data

import (
	"encoding/binary"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (e *DataClockConsensusEngine) runPreMidnightProofWorker() {
	increment, _, _, err := e.dataProofStore.GetLatestDataTimeProof(
		e.pubSub.GetPeerID(),
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.logger.Info("could not find pre-2.0 proofs")
			return
		}

		panic(err)
	}

	addrBI, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		panic(err)
	}

	addr := addrBI.FillBytes(make([]byte, 32))

	for {
		frame, err := e.dataTimeReel.Head()
		tries := e.GetFrameProverTries()

		e.peerMapMx.RLock()
		wait := false
		for _, v := range e.peerMap {
			if v.maxFrame-10 > frame.FrameNumber {
				wait = true
			}
		}
		e.peerMapMx.RUnlock()

		if len(tries) == 0 || wait {
			e.logger.Debug("waiting for more peer info to appear")
			time.Sleep(10 * time.Second)
			continue
		}

		frames, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}

		resume := make([]byte, 32)

		foundPri := -1
		for pri, pr := range prfs {
			if pr.IndexProof != nil {
				resume, err = GetAddressOfPreCoinProof(pr)
				if err != nil {
					panic(err)
				}
				increment = pr.Difficulty - 1
				foundPri = pri
				break
			}
		}

		if foundPri != -1 {
			if frame.FrameNumber == frames[foundPri] {
				e.logger.Debug("waiting for a new frame to appear")
				time.Sleep(10 * time.Second)
				continue
			}
		}

		proofs := [][]byte{
			[]byte("pre-dusk"),
			resume,
		}

		batchCount := 0
		for i := increment; i >= 0; i-- {
			_, parallelism, input, output, err := e.dataProofStore.GetDataTimeProof(
				e.pubSub.GetPeerID(),
				uint32(i),
			)
			if err == nil {
				p := []byte{}
				p = binary.BigEndian.AppendUint32(p, uint32(i))
				p = binary.BigEndian.AppendUint32(p, parallelism)
				p = binary.BigEndian.AppendUint64(p, uint64(len(input)))
				p = append(p, input...)
				p = binary.BigEndian.AppendUint64(p, uint64(len(output)))
				p = append(p, output...)

				proofs = append(proofs, p)
			} else {
				panic(err)
			}

			batchCount++
			if batchCount == 10 || i == 0 {
				payload := []byte("mint")
				for _, i := range proofs {
					payload = append(payload, i...)
				}
				sig, err := e.pubSub.SignMessage(payload)
				if err != nil {
					panic(err)
				}

				e.publishMessage(
					e.filter,
					&protobufs.TokenRequest{
						Request: &protobufs.TokenRequest_Mint{
							Mint: &protobufs.MintCoinRequest{
								Proofs: proofs,
								Signature: &protobufs.Ed448Signature{
									PublicKey: &protobufs.Ed448PublicKey{
										KeyValue: e.pubSub.GetPublicKey(),
									},
									Signature: sig,
								},
							},
						},
					},
				)

				time.Sleep(20 * time.Second)

				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil {
					for _, pr := range prfs {
						if pr.IndexProof != nil {
							resume, err = GetAddressOfPreCoinProof(pr)
							if err != nil {
								panic(err)
							}
						}
					}
				}
				batchCount = 0
				proofs = [][]byte{
					[]byte("pre-dusk"),
					resume,
				}
			}
		}
	}
}

func GetAddressOfPreCoinProof(
	proof *protobufs.PreCoinProof,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = append(eval, proof.Amount...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Index)
	eval = append(eval, proof.IndexProof...)
	eval = append(eval, proof.Commitment...)
	eval = append(eval, proof.Proof...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Parallelism)
	eval = binary.BigEndian.AppendUint32(eval, proof.Difficulty)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, proof.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}
