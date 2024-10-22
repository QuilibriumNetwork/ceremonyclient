package data

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (e *DataClockConsensusEngine) runPreMidnightProofWorker() {
	e.logger.Info("checking for pre-2.0 proofs")

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

	for {
		if e.state < consensus.EngineStateCollecting {
			e.logger.Info("waiting for node to finish starting")
			time.Sleep(10 * time.Second)
			continue
		}
		break
	}

	addrBI, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		panic(err)
	}

	addr := addrBI.FillBytes(make([]byte, 32))

	genesis := config.GetGenesis()
	pub, err := crypto.UnmarshalEd448PublicKey(genesis.Beacon)
	if err != nil {
		panic(err)
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

outer:
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
			e.logger.Info("waiting for more peer info to appear")
			time.Sleep(10 * time.Second)
			continue
		}

		cc, err := e.pubSub.GetDirectChannel([]byte(peerId), "")
		if err != nil {
			e.logger.Info(
				"could not establish direct channel, waiting...",
				zap.Error(err),
			)
			time.Sleep(10 * time.Second)
			continue
		}
		defer cc.Close()

		client := protobufs.NewDataServiceClient(cc)

		status, err := client.GetPreMidnightMintStatus(
			context.Background(),
			&protobufs.PreMidnightMintStatusRequest{
				Owner: addr,
			},
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		)
		if err != nil || status == nil {
			e.logger.Error(
				"got error response, waiting...",
				zap.Error(err),
			)
			time.Sleep(10 * time.Second)
			continue
		}

		resume := status.Address

		proofs := [][]byte{
			[]byte("pre-dusk"),
			resume,
		}

		if status.Increment != 0 {
			increment = status.Increment - 1
		}

		if status.Increment == 0 && !bytes.Equal(status.Address, make([]byte, 32)) {
			e.logger.Info("already completed pre-midnight mint")
			return
		}

		batchCount := 0
		// the cast is important, it underflows without:
		for i := int(increment); i >= 0; i-- {
			e.logger.Info("iterating proofs", zap.Int("increment", i))
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
				e.logger.Error(
					"could not find data time proof for peer and increment, stopping worker",
					zap.String("peer_id", peer.ID(e.pubSub.GetPeerID()).String()),
					zap.Int("increment", i),
				)
				return
			}

			batchCount++
			if batchCount == 100 || i == 0 {
				e.logger.Info("publishing proof batch", zap.Int("increment", i))

				payload := []byte("mint")
				for _, i := range proofs {
					payload = append(payload, i...)
				}
				sig, err := e.pubSub.SignMessage(payload)
				if err != nil {
					panic(err)
				}

				resp, err := client.HandlePreMidnightMint(
					context.Background(),
					&protobufs.MintCoinRequest{
						Proofs: proofs,
						Signature: &protobufs.Ed448Signature{
							PublicKey: &protobufs.Ed448PublicKey{
								KeyValue: e.pubSub.GetPublicKey(),
							},
							Signature: sig,
						},
					},
				)

				if err != nil {
					e.logger.Error(
						"got error response, waiting...",
						zap.Error(err),
					)
					time.Sleep(10 * time.Second)
					continue outer
				}

				time.Sleep(10 * time.Second)

				resume = resp.Address
				batchCount = 0
				proofs = [][]byte{
					[]byte("pre-dusk"),
					resume,
				}

				if i == 0 {
					e.logger.Info("pre-midnight proofs submitted, returning")
					return
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
