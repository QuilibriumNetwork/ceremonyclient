package rpc

import (
	"context"
	"os"
	"runtime"
	"syscall"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/node/crypto"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type DataWorkerIPCServer struct {
	protobufs.UnimplementedDataIPCServiceServer
	listenAddrGRPC  string
	logger          *zap.Logger
	coreId          uint32
	prover          crypto.FrameProver
	parentProcessId int
}

// GetFrameInfo implements protobufs.NodeServiceServer.
func (r *DataWorkerIPCServer) CalculateChallengeProof(
	ctx context.Context,
	req *protobufs.ChallengeProofRequest,
) (*protobufs.ChallengeProofResponse, error) {
	if r.coreId != req.Core {
		return nil, errors.Wrap(
			errors.New("invalid core id"),
			"calculate challenge proof",
		)
	}

	proof, err := r.prover.CalculateChallengeProof(
		req.Challenge,
		uint32(r.coreId),
		req.Increment,
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
