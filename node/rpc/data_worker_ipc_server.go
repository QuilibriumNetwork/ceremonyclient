package rpc

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type DataWorkerIPCServer struct {
	protobufs.UnimplementedDataIPCServiceServer
	listenAddrGRPC  string
	logger          *zap.Logger
	coreId          uint32
	prover          crypto.FrameProver
	indices         []int
	parentProcessId int
}

// GetFrameInfo implements protobufs.NodeServiceServer.
func (r *DataWorkerIPCServer) CalculateChallengeProof(
	ctx context.Context,
	req *protobufs.ChallengeProofRequest,
) (*protobufs.ChallengeProofResponse, error) {
	challenge := []byte{}
	challenge = append(challenge, req.PeerId...)
	challenge = binary.BigEndian.AppendUint64(
		challenge,
		req.ClockFrame.FrameNumber,
	)
	found := false
	for _, proof := range req.ClockFrame.AggregateProofs {
		for _, c := range proof.InclusionCommitments {
			o := &protobufs.IntrinsicExecutionOutput{}
			err := proto.Unmarshal(c.Data, o)
			if err != nil {
				return nil, err
			}

			outputs := &protobufs.TokenOutputs{}
			err = proto.Unmarshal(o.Output, outputs)
			if err != nil {
				return nil, err
			}

		inRange:
			for _, out := range outputs.Outputs {
				switch e := out.Output.(type) {
				case *protobufs.TokenOutput_Coin:
					for _, idx := range p2p.GetOnesIndices(
						p2p.GetBloomFilter(
							e.Coin.Owner.GetImplicitAccount().Address,
							1024,
							64,
						),
					) {
						for _, i := range r.indices {
							if i == idx {
								challenge = append(challenge, req.ClockFrame.Filter...)
								challenge = append(challenge, req.ClockFrame.Input...)
								challenge = append(challenge, c.Data...)
								found = true
								break inRange
							}
						}
					}
				case *protobufs.TokenOutput_DeletedCoin:
					for _, idx := range p2p.GetOnesIndices(
						p2p.GetBloomFilter(
							e.DeletedCoin.Owner.GetImplicitAccount().Address,
							1024,
							64,
						),
					) {
						for _, i := range r.indices {
							if i == idx {
								challenge = append(challenge, req.ClockFrame.Filter...)
								challenge = append(challenge, req.ClockFrame.Input...)
								challenge = append(challenge, c.Data...)
								found = true
								break inRange
							}
						}
					}
				case *protobufs.TokenOutput_DeletedProof:
					for _, idx := range p2p.GetOnesIndices(
						p2p.GetBloomFilter(
							e.DeletedProof.Owner.GetImplicitAccount().Address,
							1024,
							64,
						),
					) {
						for _, i := range r.indices {
							if i == idx {
								challenge = append(challenge, req.ClockFrame.Filter...)
								challenge = append(challenge, req.ClockFrame.Input...)
								challenge = append(challenge, c.Data...)
								found = true
								break inRange
							}
						}
					}
				case *protobufs.TokenOutput_Proof:
					for _, idx := range p2p.GetOnesIndices(
						p2p.GetBloomFilter(
							e.Proof.Owner.GetImplicitAccount().Address,
							1024,
							64,
						),
					) {
						for _, i := range r.indices {
							if i == idx {
								challenge = append(challenge, req.ClockFrame.Filter...)
								challenge = append(challenge, req.ClockFrame.Input...)
								challenge = append(challenge, c.Data...)
								found = true
								break inRange
							}
						}
					}
				}
			}
		}
	}

	if !found {
		return nil, errors.Wrap(
			errors.New("no applicable challenge"),
			"calculate challenge proof",
		)
	}
	proof, err := r.prover.CalculateChallengeProof(
		challenge,
		req.ClockFrame.Difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "calculate challenge proof")
	}

	return &protobufs.ChallengeProofResponse{
		Output: proof,
	}, nil
}

func NewDataWorkerIPCServer(
	listenAddrGRPC string,
	logger *zap.Logger,
	coreId uint32,
	prover crypto.FrameProver,
	parentProcessId int,
) (*DataWorkerIPCServer, error) {
	return &DataWorkerIPCServer{
		listenAddrGRPC:  listenAddrGRPC,
		logger:          logger,
		coreId:          coreId,
		prover:          prover,
		parentProcessId: parentProcessId,
	}, nil
}

func (r *DataWorkerIPCServer) Start() error {
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(10*1024*1024),
		grpc.MaxSendMsgSize(10*1024*1024),
	)
	protobufs.RegisterDataIPCServiceServer(s, r)
	reflection.Register(s)

	mg, err := multiaddr.NewMultiaddr(r.listenAddrGRPC)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	go r.monitorParent()

	r.logger.Info(
		"data worker listening",
		zap.String("address", r.listenAddrGRPC),
	)
	if err := s.Serve(mn.NetListener(lis)); err != nil {
		r.logger.Error("terminating server", zap.Error(err))
		panic(err)
	}

	return nil
}

func (r *DataWorkerIPCServer) monitorParent() {
	if r.parentProcessId == 0 {
		r.logger.Info(
			"no parent process id specified, running in detached worker mode",
			zap.Uint32("core_id", r.coreId),
		)
		return
	}

	for {
		time.Sleep(1 * time.Second)
		proc, err := os.FindProcess(r.parentProcessId)
		if err != nil {
			r.logger.Error("parent process not found, terminating")
			os.Exit(1)
		}

		// Windows returns an error if the process is dead, nobody else does
		if runtime.GOOS != "windows" {
			err := proc.Signal(syscall.Signal(0))
			if err != nil {
				r.logger.Error("parent process not found, terminating")
				os.Exit(1)
			}
		}
	}
}
