package rpc

import (
	"bytes"
	"context"
	"math/big"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type RPCServer struct {
	protobufs.UnimplementedNodeServiceServer
	listenAddrGRPC   string
	listenAddrHTTP   string
	logger           *zap.Logger
	clockStore       store.ClockStore
	keyManager       keys.KeyManager
	pubSub           p2p.PubSub
	executionEngines []execution.ExecutionEngine
}

// GetFrameInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetFrameInfo(
	ctx context.Context,
	req *protobufs.GetFrameInfoRequest,
) (*protobufs.FrameInfoResponse, error) {
	if bytes.Equal(req.Filter, p2p.BITMASK_ALL) {
		frame, err := r.clockStore.GetMasterClockFrame(
			req.Filter,
			req.FrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		return &protobufs.FrameInfoResponse{
			ClockFrame: frame,
		}, nil
	} else if req.Selector == nil {
		frame, _, err := r.clockStore.GetDataClockFrame(
			req.Filter,
			req.FrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		return &protobufs.FrameInfoResponse{
			ClockFrame: frame,
		}, nil
	} else {
		frames, err := r.clockStore.GetCandidateDataClockFrames(
			req.Filter,
			req.FrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		for _, frame := range frames {
			selector, err := frame.GetSelector()
			if err != nil {
				return nil, errors.Wrap(err, "get frame info")
			}

			if bytes.Equal(selector.Bytes(), req.Selector) {
				return &protobufs.FrameInfoResponse{
					ClockFrame: frame,
				}, nil
			}
		}

		return nil, errors.Wrap(errors.New("not found"), "get frame info")
	}
}

// GetFrames implements protobufs.NodeServiceServer.
func (r *RPCServer) GetFrames(
	ctx context.Context,
	req *protobufs.GetFramesRequest,
) (*protobufs.FramesResponse, error) {
	if bytes.Equal(req.Filter, p2p.BITMASK_ALL) {
		iter, err := r.clockStore.RangeMasterClockFrames(
			req.Filter,
			req.FromFrameNumber,
			req.ToFrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		frames := []*protobufs.ClockFrame{}
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			if err != nil {
				iter.Close()
				return nil, errors.Wrap(err, "get frames")
			}
			frames = append(frames, frame)
		}

		if err := iter.Close(); err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		return &protobufs.FramesResponse{
			TruncatedClockFrames: frames,
		}, nil
	} else {
		iter, err := r.clockStore.RangeDataClockFrames(
			req.Filter,
			req.FromFrameNumber,
			req.ToFrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		frames := []*protobufs.ClockFrame{}
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.TruncatedValue()
			if err != nil {
				iter.Close()
				return nil, errors.Wrap(err, "get frames")
			}
			frames = append(frames, frame)
		}

		if err := iter.Close(); err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		if req.IncludeCandidates {
			from := req.FromFrameNumber
			if len(frames) > 0 {
				from = frames[len(frames)-1].FrameNumber + 1
			}

			for from < req.ToFrameNumber {
				iter, err := r.clockStore.RangeCandidateDataClockFrames(
					req.Filter,
					[]byte{
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					},
					from,
				)
				if err != nil {
					return nil, errors.Wrap(err, "get frames")
				}

				for iter.First(); iter.Valid(); iter.Next() {
					frame, err := iter.TruncatedValue()
					if err != nil {
						iter.Close()
						return nil, errors.Wrap(err, "get frames")
					}
					frames = append(frames, frame)
				}

				if err := iter.Close(); err != nil {
					return nil, errors.Wrap(err, "get frames")
				}

				from++
			}
		}

		return &protobufs.FramesResponse{
			TruncatedClockFrames: frames,
		}, nil
	}
}

// GetNetworkInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetNetworkInfo(
	ctx context.Context,
	req *protobufs.GetNetworkInfoRequest,
) (*protobufs.NetworkInfoResponse, error) {
	return r.pubSub.GetNetworkInfo(), nil
}

// GetPeerInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetPeerInfo(
	ctx context.Context,
	req *protobufs.GetPeerInfoRequest,
) (*protobufs.PeerInfoResponse, error) {
	resp := &protobufs.PeerInfoResponse{}
	for _, e := range r.executionEngines {
		r := e.GetPeerInfo()
		resp.PeerInfo = append(resp.PeerInfo, r.PeerInfo...)
		resp.UncooperativePeerInfo = append(
			resp.UncooperativePeerInfo,
			r.UncooperativePeerInfo...,
		)
	}
	return resp, nil
}

func (r *RPCServer) GetTokenInfo(
	ctx context.Context,
	req *protobufs.GetTokenInfoRequest,
) (*protobufs.TokenInfoResponse, error) {
	provingKey, err := r.keyManager.GetRawKey(
		"default-proving-key",
	)
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	addr, err := poseidon.HashBytes(provingKey.PublicKey)
	if err != nil {
		panic(err)
	}

	addrBytes := addr.Bytes()
	addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)

	frame, err := r.clockStore.GetLatestDataClockFrame(
		application.CEREMONY_ADDRESS,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	confirmed, err := application.MaterializeApplicationFromFrame(frame)
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	confirmedTotal := new(big.Int)
	unconfirmedTotal := new(big.Int)
	ownedTotal := new(big.Int)
	if confirmed.RewardTrie.Root == nil ||
		(confirmed.RewardTrie.Root.External == nil &&
			confirmed.RewardTrie.Root.Internal == nil) {
		return &protobufs.TokenInfoResponse{
			ConfirmedTokenSupply:   confirmedTotal.FillBytes(make([]byte, 32)),
			UnconfirmedTokenSupply: unconfirmedTotal.FillBytes(make([]byte, 32)),
			OwnedTokens:            ownedTotal.FillBytes(make([]byte, 32)),
		}, nil
	}

	limbs := []*tries.RewardInternalNode{}
	if confirmed.RewardTrie.Root.Internal != nil {
		limbs = append(limbs, confirmed.RewardTrie.Root.Internal)
	} else {
		confirmedTotal = confirmedTotal.Add(
			confirmedTotal,
			new(big.Int).SetUint64(confirmed.RewardTrie.Root.External.Total),
		)
		if bytes.Equal(
			confirmed.RewardTrie.Root.External.Key,
			addrBytes,
		) {
			ownedTotal = ownedTotal.Add(
				ownedTotal,
				new(big.Int).SetUint64(confirmed.RewardTrie.Root.External.Total),
			)
		}
	}

	for len(limbs) != 0 {
		nextLimbs := []*tries.RewardInternalNode{}
		for _, limb := range limbs {
			for _, child := range limb.Child {
				child := child
				if child.Internal != nil {
					nextLimbs = append(nextLimbs, child.Internal)
				} else {
					confirmedTotal = confirmedTotal.Add(
						confirmedTotal,
						new(big.Int).SetUint64(child.External.Total),
					)
					if bytes.Equal(
						child.External.Key,
						addrBytes,
					) {
						ownedTotal = ownedTotal.Add(
							ownedTotal,
							new(big.Int).SetUint64(child.External.Total),
						)
					}
				}
			}
		}
		limbs = nextLimbs
	}

	candidateFrame, err := r.clockStore.GetHighestCandidateDataClockFrame(
		application.CEREMONY_ADDRESS,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	unconfirmed, err := application.MaterializeApplicationFromFrame(
		candidateFrame,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get token info")
	}

	limbs = []*tries.RewardInternalNode{}
	if unconfirmed.RewardTrie.Root.Internal != nil {
		limbs = append(limbs, unconfirmed.RewardTrie.Root.Internal)
	} else {
		unconfirmedTotal = unconfirmedTotal.Add(
			unconfirmedTotal,
			new(big.Int).SetUint64(unconfirmed.RewardTrie.Root.External.Total),
		)
	}

	for len(limbs) != 0 {
		nextLimbs := []*tries.RewardInternalNode{}
		for _, limb := range limbs {
			for _, child := range limb.Child {
				child := child
				if child.Internal != nil {
					nextLimbs = append(nextLimbs, child.Internal)
				} else {
					unconfirmedTotal = unconfirmedTotal.Add(
						unconfirmedTotal,
						new(big.Int).SetUint64(child.External.Total),
					)
				}
			}
		}
		limbs = nextLimbs
	}

	// 1 QUIL = 0x1DCD65000 units
	conversionFactor, ok := new(big.Int).SetString("1DCD65000", 16)
	if !ok {
		return nil, errors.Wrap(err, "get token info")
	}

	confirmedTotal = confirmedTotal.Mul(confirmedTotal, conversionFactor)
	unconfirmedTotal = unconfirmedTotal.Mul(unconfirmedTotal, conversionFactor)
	ownedTotal = ownedTotal.Mul(ownedTotal, conversionFactor)

	return &protobufs.TokenInfoResponse{
		ConfirmedTokenSupply:   confirmedTotal.FillBytes(make([]byte, 32)),
		UnconfirmedTokenSupply: unconfirmedTotal.FillBytes(make([]byte, 32)),
		OwnedTokens:            ownedTotal.FillBytes(make([]byte, 32)),
	}, nil
}

func NewRPCServer(
	listenAddrGRPC string,
	listenAddrHTTP string,
	logger *zap.Logger,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	executionEngines []execution.ExecutionEngine,
) (*RPCServer, error) {
	return &RPCServer{
		listenAddrGRPC:   listenAddrGRPC,
		listenAddrHTTP:   listenAddrHTTP,
		logger:           logger,
		clockStore:       clockStore,
		keyManager:       keyManager,
		pubSub:           pubSub,
		executionEngines: executionEngines,
	}, nil
}

func (r *RPCServer) Start() error {
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(600*1024*1024),
		grpc.MaxSendMsgSize(600*1024*1024),
	)
	protobufs.RegisterNodeServiceServer(s, r)
	reflection.Register(s)

	mg, err := multiaddr.NewMultiaddr(r.listenAddrGRPC)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	go func() {
		if err := s.Serve(mn.NetListener(lis)); err != nil {
			panic(err)
		}
	}()

	if r.listenAddrHTTP != "" {
		m, err := multiaddr.NewMultiaddr(r.listenAddrHTTP)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		ma, err := mn.ToNetAddr(m)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		mga, err := mn.ToNetAddr(mg)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		go func() {
			mux := runtime.NewServeMux()
			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(
					grpc.MaxCallRecvMsgSize(600*1024*1024),
					grpc.MaxCallSendMsgSize(600*1024*1024),
				),
			}

			if err := protobufs.RegisterNodeServiceHandlerFromEndpoint(
				context.Background(),
				mux,
				mga.String(),
				opts,
			); err != nil {
				panic(err)
			}

			if err := http.ListenAndServe(ma.String(), mux); err != nil {
				panic(err)
			}
		}()
	}

	return nil
}
