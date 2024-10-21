package data

import (
	"context"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var ErrNoNewFrames = errors.New("peer reported no frames")

func (e *DataClockConsensusEngine) GetDataFrame(
	ctx context.Context,
	request *protobufs.GetDataFrameRequest,
) (*protobufs.DataFrameResponse, error) {
	e.logger.Debug(
		"received frame request",
		zap.Uint64("frame_number", request.FrameNumber),
	)
	var frame *protobufs.ClockFrame
	var err error
	if request.FrameNumber == 0 {
		frame, err = e.dataTimeReel.Head()
		if frame.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get data frame",
			)
		}
	} else {
		frame, _, err = e.clockStore.GetDataClockFrame(
			e.filter,
			request.FrameNumber,
			false,
		)
	}

	if err != nil {
		e.logger.Error(
			"received error while fetching time reel head",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get data frame")
	}

	return &protobufs.DataFrameResponse{
		ClockFrame: frame,
	}, nil
}

func (e *DataClockConsensusEngine) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return nil
}

// Deprecated: Use NegotiateCompressedSyncFrames.
// GetCompressedSyncFrames implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	e.logger.Debug(
		"received clock frame request",
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
	)

	if err := server.SendMsg(
		&protobufs.ClockFramesResponse{
			Filter:          request.Filter,
			FromFrameNumber: 0,
			ToFrameNumber:   0,
			ClockFrames:     []*protobufs.ClockFrame{},
		},
	); err != nil {
		return errors.Wrap(err, "get compressed sync frames")
	}

	return nil
}

type svr struct {
	protobufs.UnimplementedDataServiceServer
	svrChan chan protobufs.DataService_GetPublicChannelServer
}

func (e *svr) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	go func() {
		e.svrChan <- server
	}()
	<-server.Context().Done()
	return nil
}

func (e *DataClockConsensusEngine) GetPublicChannelForProvingKey(
	initiator bool,
	peerID []byte,
	provingKey []byte,
) (p2p.PublicChannelClient, error) {
	if initiator {
		svrChan := make(
			chan protobufs.DataService_GetPublicChannelServer,
		)
		after := time.After(20 * time.Second)
		go func() {
			server := grpc.NewServer(
				grpc.MaxSendMsgSize(600*1024*1024),
				grpc.MaxRecvMsgSize(600*1024*1024),
			)

			s := &svr{
				svrChan: svrChan,
			}
			protobufs.RegisterDataServiceServer(server, s)

			if err := e.pubSub.StartDirectChannelListener(
				peerID,
				base58.Encode(provingKey),
				server,
			); err != nil {
				e.logger.Error(
					"could not get public channel for proving key",
					zap.Error(err),
				)
				svrChan <- nil
			}
		}()
		select {
		case s := <-svrChan:
			return s, nil
		case <-after:
			return nil, errors.Wrap(
				errors.New("timed out"),
				"get public channel for proving key",
			)
		}
	} else {
		cc, err := e.pubSub.GetDirectChannel(peerID, base58.Encode(provingKey))
		if err != nil {
			e.logger.Error(
				"could not get public channel for proving key",
				zap.Error(err),
			)
			return nil, nil
		}
		client := protobufs.NewDataServiceClient(cc)
		s, err := client.GetPublicChannel(
			context.Background(),
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		)
		return s, errors.Wrap(err, "get public channel for proving key")
	}
}

// GetPublicChannel implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	return errors.New("not supported")
}
