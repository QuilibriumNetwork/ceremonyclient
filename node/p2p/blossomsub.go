package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoreds"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type BlossomSub struct {
	ps              *blossomsub.PubSub
	ctx             context.Context
	logger          *zap.Logger
	peerID          peer.ID
	bitmaskMap      map[string]*blossomsub.Bitmask
	h               host.Host
	signKey         crypto.PrivKey
	peerScore       map[string]int64
	peerScoreMx     sync.Mutex
	isBootstrapPeer bool
	network         uint8
}

var _ PubSub = (*BlossomSub)(nil)
var ErrNoPeersAvailable = errors.New("no peers available")

var BITMASK_ALL = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// While we iterate through these next phases, we're going to aggressively
// enforce keeping updated. This will be achieved through announce strings
// that will vary with each update
var ANNOUNCE_PREFIX = "quilibrium-1.4.20-solstice-"

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return id
}

func NewBlossomSub(
	p2pConfig *config.P2PConfig,
	peerstore store.Peerstore,
	logger *zap.Logger,
) *BlossomSub {
	ctx := context.Background()

	opts := []libp2pconfig.Option{
		libp2p.ListenAddrStrings(p2pConfig.ListenMultiaddr),
	}

	isBootstrapPeer := false
	peerId := getPeerID(p2pConfig)

	for _, peerAddr := range config.BootstrapPeers {
		peerinfo, err := peer.AddrInfoFromString(peerAddr)
		if err != nil {
			panic(err)
		}

		if bytes.Equal([]byte(peerinfo.ID), []byte(peerId)) {
			isBootstrapPeer = true
			break
		}
	}

	var privKey crypto.PrivKey
	if p2pConfig.PeerPrivKey != "" {
		peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
		if err != nil {
			panic(errors.Wrap(err, "error unmarshaling peerkey"))
		}

		privKey, err = crypto.UnmarshalEd448PrivateKey(peerPrivKey)
		if err != nil {
			panic(errors.Wrap(err, "error unmarshaling peerkey"))
		}

		opts = append(opts, libp2p.Identity(privKey))
	}

	ps, err := pstoreds.NewPeerstore(ctx, peerstore, pstoreds.DefaultOpts())
	if err != nil {
		panic(err)
	}

	opts = append(opts, libp2p.Peerstore(ps))

	bs := &BlossomSub{
		ctx:             ctx,
		logger:          logger,
		bitmaskMap:      make(map[string]*blossomsub.Bitmask),
		signKey:         privKey,
		peerScore:       make(map[string]int64),
		isBootstrapPeer: isBootstrapPeer,
		network:         p2pConfig.Network,
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		panic(errors.Wrap(err, "error constructing p2p"))
	}

	logger.Info("established peer id", zap.String("peer_id", h.ID().String()))

	kademliaDHT := initDHT(ctx, p2pConfig, logger, h, isBootstrapPeer)
	routingDiscovery := routing.NewRoutingDiscovery(kademliaDHT)
	util.Advertise(ctx, routingDiscovery, getNetworkNamespace(p2pConfig.Network))

	discoverPeers(p2pConfig, ctx, logger, h, routingDiscovery)

	// TODO: turn into an option flag for console logging, this is too noisy for
	// default logging behavior
	var tracer *blossomsub.JSONTracer
	if p2pConfig.TraceLogFile == "" {
		// tracer, err = blossomsub.NewStdoutJSONTracer()
		// if err != nil {
		// 	panic(errors.Wrap(err, "error building stdout tracer"))
		// }
	} else {
		tracer, err = blossomsub.NewJSONTracer(p2pConfig.TraceLogFile)
		if err != nil {
			panic(errors.Wrap(err, "error building file tracer"))
		}
	}

	blossomOpts := []blossomsub.Option{}
	if isBootstrapPeer {
		blossomOpts = append(blossomOpts,
			blossomsub.WithPeerExchange(true),
		)
	}

	if tracer != nil {
		blossomOpts = append(blossomOpts, blossomsub.WithEventTracer(tracer))
	}
	blossomOpts = append(blossomOpts, blossomsub.WithPeerScore(
		&blossomsub.PeerScoreParams{
			SkipAtomicValidation:        false,
			BitmaskScoreCap:             0,
			IPColocationFactorWeight:    0,
			IPColocationFactorThreshold: 6,
			BehaviourPenaltyWeight:      0,
			BehaviourPenaltyThreshold:   100,
			BehaviourPenaltyDecay:       .5,
			DecayInterval:               10 * time.Second,
			DecayToZero:                 .1,
			RetainScore:                 60 * time.Minute,
			AppSpecificScore: func(p peer.ID) float64 {
				return float64(bs.GetPeerScore([]byte(p)))
			},
			AppSpecificWeight: 10.0,
		},
		&blossomsub.PeerScoreThresholds{
			SkipAtomicValidation:        false,
			GossipThreshold:             -2000,
			PublishThreshold:            -5000,
			GraylistThreshold:           -10000,
			AcceptPXThreshold:           1,
			OpportunisticGraftThreshold: 2,
		}))

	params := mergeDefaults(p2pConfig)
	rt := blossomsub.NewBlossomSubRouter(h, params)
	pubsub, err := blossomsub.NewBlossomSubWithRouter(ctx, h, rt, blossomOpts...)
	if err != nil {
		panic(err)
	}

	peerID := h.ID()
	bs.ps = pubsub
	bs.peerID = peerID
	bs.h = h
	bs.signKey = privKey

	return bs
}

func (b *BlossomSub) PublishToBitmask(bitmask []byte, data []byte) error {
	networkBitmask := append([]byte{b.network}, bitmask...)
	bm, ok := b.bitmaskMap[string(networkBitmask)]
	if !ok {
		b.logger.Error(
			"error while publishing to bitmask",
			zap.Error(errors.New("not subscribed to bitmask")),
			zap.Binary("bitmask", bitmask),
		)
		return errors.New("not subscribed to bitmask")
	}

	return bm.Publish(b.ctx, data)
}

func (b *BlossomSub) Publish(data []byte) error {
	bitmask := GetBloomFilter(data, 256, 3)
	bitmask = append(bitmask, GetBloomFilterIndices(data, 65536, 24)...)
	return b.PublishToBitmask(bitmask, data)
}

func (b *BlossomSub) Subscribe(
	bitmask []byte,
	handler func(message *pb.Message) error,
	raw bool,
) {
	eval := func(bitmask []byte) error {
		networkBitmask := append([]byte{b.network}, bitmask...)
		_, ok := b.bitmaskMap[string(networkBitmask)]
		if ok {
			return nil
		}

		b.logger.Info("joining broadcast")
		bm, err := b.ps.Join(networkBitmask)
		if err != nil {
			b.logger.Error("join failed", zap.Error(err))
			return errors.Wrap(err, "subscribe")
		}

		b.bitmaskMap[string(networkBitmask)] = bm

		b.logger.Info("subscribe to bitmask", zap.Binary("bitmask", bitmask))
		sub, err := bm.Subscribe()
		if err != nil {
			b.logger.Error("subscription failed", zap.Error(err))
			return errors.Wrap(err, "subscribe")
		}

		b.logger.Info(
			"begin streaming from bitmask",
			zap.Binary("bitmask", bitmask),
		)

		go func() {
			for {
				m, err := sub.Next(b.ctx)
				if err != nil {
					b.logger.Error(
						"got error when fetching the next message",
						zap.Error(err),
					)
				}
				if err = handler(m.Message); err != nil {
					b.logger.Debug("message handler returned error", zap.Error(err))
				}
			}
		}()

		return nil
	}

	if raw {
		if err := eval(bitmask); err != nil {
			b.logger.Error("subscribe returned error", zap.Error(err))
		}
	} else {
		if err := generateBitSlices(bitmask, eval); err != nil {
			b.logger.Error("bloom subscribe returned error", zap.Error(err))
		}
	}
}

func (b *BlossomSub) Unsubscribe(bitmask []byte, raw bool) {
	networkBitmask := append([]byte{b.network}, bitmask...)
	bm, ok := b.bitmaskMap[string(networkBitmask)]
	if !ok {
		return
	}

	bm.Close()
}

func (b *BlossomSub) GetPeerID() []byte {
	return []byte(b.peerID)
}

func (b *BlossomSub) GetRandomPeer(bitmask []byte) ([]byte, error) {
	networkBitmask := append([]byte{b.network}, bitmask...)
	peers := b.ps.ListPeers(networkBitmask)
	if len(peers) == 0 {
		return nil, errors.Wrap(
			ErrNoPeersAvailable,
			"get random peer",
		)
	}
	b.logger.Debug("selecting from peers", zap.Any("peer_ids", peers))
	sel, err := rand.Int(rand.Reader, big.NewInt(int64(len(peers))))
	if err != nil {
		return nil, errors.Wrap(err, "get random peer")
	}

	return []byte(peers[sel.Int64()]), nil
}

func initDHT(
	ctx context.Context,
	p2pConfig *config.P2PConfig,
	logger *zap.Logger,
	h host.Host,
	isBootstrapPeer bool,
) *dht.IpfsDHT {
	logger.Info("establishing dht")
	var kademliaDHT *dht.IpfsDHT
	var err error
	if isBootstrapPeer {
		kademliaDHT, err = dht.New(ctx, h, dht.Mode(dht.ModeServer))
	} else {
		// until libp2p gets their shit together, set this as a client only:
		kademliaDHT, err = dht.New(ctx, h, dht.Mode(dht.ModeClient))
	}
	if err != nil {
		panic(err)
	}
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		panic(err)
	}

	reconnect := func() {
		logger.Info(
			"connecting to bootstrap",
			zap.String("peer_id", h.ID().String()),
		)

		defaultBootstrapPeers := append([]string{}, p2pConfig.BootstrapPeers...)

		if p2pConfig.Network == 0 {
			for _, peer := range config.BootstrapPeers {
				found := false
				for _, existing := range defaultBootstrapPeers {
					if existing == peer {
						found = true
						break
					}
				}
				if !found {
					defaultBootstrapPeers = append(defaultBootstrapPeers, peer)
				}
			}
		}

		for _, peerAddr := range defaultBootstrapPeers {
			peerinfo, err := peer.AddrInfoFromString(peerAddr)
			if err != nil {
				panic(err)
			}

			if peerinfo.ID == h.ID() ||
				h.Network().Connectedness(peerinfo.ID) == network.Connected ||
				h.Network().Connectedness(peerinfo.ID) == network.CannotConnect {
				continue
			}

			if err := h.Connect(ctx, *peerinfo); err != nil {
				logger.Debug("error while connecting to dht peer", zap.Error(err))
			} else {
				logger.Debug(
					"connected to peer",
					zap.String("peer_id", peerinfo.ID.String()),
				)
			}
		}
	}

	reconnect()

	go func() {
		for {
			time.Sleep(30 * time.Second)
			logger.Debug("reconnecting to peers")
			reconnect()
		}
	}()

	return kademliaDHT
}

func (b *BlossomSub) GetPeerScore(peerId []byte) int64 {
	b.peerScoreMx.Lock()
	score := b.peerScore[string(peerId)]
	b.peerScoreMx.Unlock()
	return score
}

func (b *BlossomSub) SetPeerScore(peerId []byte, score int64) {
	b.peerScoreMx.Lock()
	b.peerScore[string(peerId)] = score
	b.peerScoreMx.Unlock()
}

func (b *BlossomSub) GetBitmaskPeers() map[string][]string {
	peers := map[string][]string{}

	for _, k := range b.bitmaskMap {
		peers[fmt.Sprintf("%+x", k.Bitmask()[1:])] = []string{}

		for _, p := range k.ListPeers() {
			peers[fmt.Sprintf("%+x", k.Bitmask()[1:])] = append(
				peers[fmt.Sprintf("%+x", k.Bitmask()[1:])],
				p.String(),
			)
		}
	}

	return peers
}

func (b *BlossomSub) GetPeerstoreCount() int {
	return len(b.h.Peerstore().Peers())
}

func (b *BlossomSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	resp := &protobufs.NetworkInfoResponse{}
	for _, p := range b.h.Network().Peers() {
		addrs := b.h.Peerstore().Addrs(p)
		multiaddrs := []string{}
		for _, a := range addrs {
			multiaddrs = append(multiaddrs, a.String())
		}
		resp.NetworkInfo = append(resp.NetworkInfo, &protobufs.NetworkInfo{
			PeerId:     []byte(p),
			Multiaddrs: multiaddrs,
			PeerScore:  b.ps.PeerScore(p),
		})
	}
	return resp
}

func (b *BlossomSub) GetNetworkPeersCount() int {
	return len(b.h.Network().Peers())
}

func (b *BlossomSub) GetMultiaddrOfPeerStream(
	ctx context.Context,
	peerId []byte,
) <-chan multiaddr.Multiaddr {
	return b.h.Peerstore().AddrStream(ctx, peer.ID(peerId))
}

func (b *BlossomSub) GetMultiaddrOfPeer(peerId []byte) string {
	addrs := b.h.Peerstore().Addrs(peer.ID(peerId))
	if len(addrs) == 0 {
		return ""
	}

	return addrs[0].String()
}

func (b *BlossomSub) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	bind, err := gostream.Listen(
		b.h,
		protocol.ID(
			"/p2p/direct-channel/"+base58.Encode(key)+purpose,
		),
	)
	if err != nil {
		return errors.Wrap(err, "start direct channel listener")
	}

	return errors.Wrap(server.Serve(bind), "start direct channel listener")
}

func (b *BlossomSub) GetDirectChannel(key []byte, purpose string) (
	dialCtx *grpc.ClientConn,
	err error,
) {
	// Kind of a weird hack, but gostream can induce panics if the peer drops at
	// the time of connection, this avoids the problem.
	defer func() {
		if r := recover(); r != nil {
			dialCtx = nil
			err = errors.New("connection failed")
		}
	}()

	// Open question: should we prefix this so a node can run both in mainnet and
	// testnet? Feels like a bad idea and would be preferable to discourage.
	dialCtx, err = grpc.DialContext(
		b.ctx,
		base58.Encode(key),
		grpc.WithDialer(
			func(peerIdStr string, timeout time.Duration) (net.Conn, error) {
				subCtx, subCtxCancel := context.WithTimeout(b.ctx, timeout)
				defer subCtxCancel()

				id, err := peer.Decode(peerIdStr)
				if err != nil {
					return nil, errors.Wrap(err, "dial context")
				}

				c, err := gostream.Dial(
					subCtx,
					b.h,
					peer.ID(key),
					protocol.ID(
						"/p2p/direct-channel/"+peer.ID(id).String()+purpose,
					),
				)

				return c, errors.Wrap(err, "dial context")
			},
		),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get direct channel")
	}

	return dialCtx, nil
}

func (b *BlossomSub) GetPublicKey() []byte {
	pub, _ := b.signKey.GetPublic().Raw()
	return pub
}

func (b *BlossomSub) SignMessage(msg []byte) ([]byte, error) {
	sig, err := b.signKey.Sign(msg)
	return sig, errors.Wrap(err, "sign message")
}

func discoverPeers(
	p2pConfig *config.P2PConfig,
	ctx context.Context,
	logger *zap.Logger,
	h host.Host,
	routingDiscovery *routing.RoutingDiscovery,
) {
	logger.Info("initiating peer discovery")

	discover := func() {
		peerChan, err := routingDiscovery.FindPeers(
			ctx,
			getNetworkNamespace(p2pConfig.Network),
		)
		if err != nil {
			logger.Error("could not find peers", zap.Error(err))
		}

		for peer := range peerChan {
			peer := peer
			if peer.ID == h.ID() ||
				h.Network().Connectedness(peer.ID) == network.Connected ||
				h.Network().Connectedness(peer.ID) == network.CannotConnect {
				continue
			}

			logger.Debug("found peer", zap.String("peer_id", peer.ID.String()))
			err := h.Connect(ctx, peer)
			if err != nil {
				logger.Debug(
					"error while connecting to blossomsub peer",
					zap.String("peer_id", peer.ID.String()),
					zap.Error(err),
				)
			} else {
				logger.Debug(
					"connected to peer",
					zap.String("peer_id", peer.ID.String()),
				)
			}
		}
	}

	discover()

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			if len(h.Network().Peers()) < 16 {
				discover()
			}
		}
	}()

	logger.Info("completed initial peer discovery")
}

func mergeDefaults(p2pConfig *config.P2PConfig) blossomsub.BlossomSubParams {
	if p2pConfig.D == 0 {
		p2pConfig.D = blossomsub.BlossomSubD
	}
	if p2pConfig.DLo == 0 {
		p2pConfig.DLo = blossomsub.BlossomSubDlo
	}
	if p2pConfig.DHi == 0 {
		p2pConfig.DHi = blossomsub.BlossomSubDhi
	}
	if p2pConfig.DScore == 0 {
		p2pConfig.DScore = blossomsub.BlossomSubDscore
	}
	if p2pConfig.DOut == 0 {
		p2pConfig.DOut = blossomsub.BlossomSubDout
	}
	if p2pConfig.HistoryLength == 0 {
		p2pConfig.HistoryLength = blossomsub.BlossomSubHistoryLength
	}
	if p2pConfig.HistoryGossip == 0 {
		p2pConfig.HistoryGossip = blossomsub.BlossomSubHistoryGossip
	}
	if p2pConfig.DLazy == 0 {
		p2pConfig.DLazy = blossomsub.BlossomSubDlazy
	}
	if p2pConfig.GossipFactor == 0 {
		p2pConfig.GossipFactor = blossomsub.BlossomSubGossipFactor
	}
	if p2pConfig.GossipRetransmission == 0 {
		p2pConfig.GossipRetransmission = blossomsub.BlossomSubGossipRetransmission
	}
	if p2pConfig.HeartbeatInitialDelay == 0 {
		p2pConfig.HeartbeatInitialDelay = blossomsub.BlossomSubHeartbeatInitialDelay
	}
	if p2pConfig.HeartbeatInterval == 0 {
		p2pConfig.HeartbeatInterval = blossomsub.BlossomSubHeartbeatInterval
	}
	if p2pConfig.FanoutTTL == 0 {
		p2pConfig.FanoutTTL = blossomsub.BlossomSubFanoutTTL
	}
	if p2pConfig.PrunePeers == 0 {
		p2pConfig.PrunePeers = blossomsub.BlossomSubPrunePeers
	}
	if p2pConfig.PruneBackoff == 0 {
		p2pConfig.PruneBackoff = blossomsub.BlossomSubPruneBackoff
	}
	if p2pConfig.UnsubscribeBackoff == 0 {
		p2pConfig.UnsubscribeBackoff = blossomsub.BlossomSubUnsubscribeBackoff
	}
	if p2pConfig.Connectors == 0 {
		p2pConfig.Connectors = blossomsub.BlossomSubConnectors
	}
	if p2pConfig.MaxPendingConnections == 0 {
		p2pConfig.MaxPendingConnections = blossomsub.BlossomSubMaxPendingConnections
	}
	if p2pConfig.ConnectionTimeout == 0 {
		p2pConfig.ConnectionTimeout = blossomsub.BlossomSubConnectionTimeout
	}
	if p2pConfig.DirectConnectTicks == 0 {
		p2pConfig.DirectConnectTicks = blossomsub.BlossomSubDirectConnectTicks
	}
	if p2pConfig.DirectConnectInitialDelay == 0 {
		p2pConfig.DirectConnectInitialDelay =
			blossomsub.BlossomSubDirectConnectInitialDelay
	}
	if p2pConfig.OpportunisticGraftTicks == 0 {
		p2pConfig.OpportunisticGraftTicks =
			blossomsub.BlossomSubOpportunisticGraftTicks
	}
	if p2pConfig.OpportunisticGraftPeers == 0 {
		p2pConfig.OpportunisticGraftPeers =
			blossomsub.BlossomSubOpportunisticGraftPeers
	}
	if p2pConfig.GraftFloodThreshold == 0 {
		p2pConfig.GraftFloodThreshold = blossomsub.BlossomSubGraftFloodThreshold
	}
	if p2pConfig.MaxIHaveLength == 0 {
		p2pConfig.MaxIHaveLength = blossomsub.BlossomSubMaxIHaveLength
	}
	if p2pConfig.MaxIHaveMessages == 0 {
		p2pConfig.MaxIHaveMessages = blossomsub.BlossomSubMaxIHaveMessages
	}
	if p2pConfig.IWantFollowupTime == 0 {
		p2pConfig.IWantFollowupTime = blossomsub.BlossomSubIWantFollowupTime
	}

	return blossomsub.BlossomSubParams{
		D:                         p2pConfig.D,
		Dlo:                       p2pConfig.DLo,
		Dhi:                       p2pConfig.DHi,
		Dscore:                    p2pConfig.DScore,
		Dout:                      p2pConfig.DOut,
		HistoryLength:             p2pConfig.HistoryLength,
		HistoryGossip:             p2pConfig.HistoryGossip,
		Dlazy:                     p2pConfig.DLazy,
		GossipFactor:              p2pConfig.GossipFactor,
		GossipRetransmission:      p2pConfig.GossipRetransmission,
		HeartbeatInitialDelay:     p2pConfig.HeartbeatInitialDelay,
		HeartbeatInterval:         p2pConfig.HeartbeatInterval,
		FanoutTTL:                 p2pConfig.FanoutTTL,
		PrunePeers:                p2pConfig.PrunePeers,
		PruneBackoff:              p2pConfig.PruneBackoff,
		UnsubscribeBackoff:        p2pConfig.UnsubscribeBackoff,
		Connectors:                p2pConfig.Connectors,
		MaxPendingConnections:     p2pConfig.MaxPendingConnections,
		ConnectionTimeout:         p2pConfig.ConnectionTimeout,
		DirectConnectTicks:        p2pConfig.DirectConnectTicks,
		DirectConnectInitialDelay: p2pConfig.DirectConnectInitialDelay,
		OpportunisticGraftTicks:   p2pConfig.OpportunisticGraftTicks,
		OpportunisticGraftPeers:   p2pConfig.OpportunisticGraftPeers,
		GraftFloodThreshold:       p2pConfig.GraftFloodThreshold,
		MaxIHaveLength:            p2pConfig.MaxIHaveLength,
		MaxIHaveMessages:          p2pConfig.MaxIHaveMessages,
		IWantFollowupTime:         p2pConfig.IWantFollowupTime,
		SlowHeartbeatWarning:      0.1,
	}
}

func getNetworkNamespace(network uint8) string {
	var network_name string
	switch network {
	case 0:
		network_name = "mainnet"
		break
	case 1:
		network_name = "testnet-primary"
		break
	default:
		network_name = fmt.Sprintf("network-%d", network)
		break
	}

	return ANNOUNCE_PREFIX + network_name
}
