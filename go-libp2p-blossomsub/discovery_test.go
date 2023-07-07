package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

type mockDiscoveryServer struct {
	mx sync.Mutex
	db map[string]map[peer.ID]*discoveryRegistration
}

type discoveryRegistration struct {
	info peer.AddrInfo
	ttl  time.Duration
}

func newDiscoveryServer() *mockDiscoveryServer {
	return &mockDiscoveryServer{
		db: make(map[string]map[peer.ID]*discoveryRegistration),
	}
}

func (s *mockDiscoveryServer) Advertise(ns string, info peer.AddrInfo, ttl time.Duration) (time.Duration, error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	peers, ok := s.db[ns]
	if !ok {
		peers = make(map[peer.ID]*discoveryRegistration)
		s.db[ns] = peers
	}
	peers[info.ID] = &discoveryRegistration{info, ttl}
	return ttl, nil
}

func (s *mockDiscoveryServer) FindPeers(ns string, limit int) (<-chan peer.AddrInfo, error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	peers, ok := s.db[ns]
	if !ok || len(peers) == 0 {
		emptyCh := make(chan peer.AddrInfo)
		close(emptyCh)
		return emptyCh, nil
	}

	count := len(peers)
	if count > limit {
		count = limit
	}
	ch := make(chan peer.AddrInfo, count)
	numSent := 0
	for _, reg := range peers {
		if numSent == count {
			break
		}
		numSent++
		ch <- reg.info
	}
	close(ch)

	return ch, nil
}

func (s *mockDiscoveryServer) hasPeerRecord(ns string, pid peer.ID) bool {
	s.mx.Lock()
	defer s.mx.Unlock()

	if peers, ok := s.db[ns]; ok {
		_, ok := peers[pid]
		return ok
	}
	return false
}

type mockDiscoveryClient struct {
	host   host.Host
	server *mockDiscoveryServer
}

func (d *mockDiscoveryClient) Advertise(ctx context.Context, ns string, opts ...discovery.Option) (time.Duration, error) {
	var options discovery.Options
	err := options.Apply(opts...)
	if err != nil {
		return 0, err
	}

	return d.server.Advertise(ns, *host.InfoFromHost(d.host), options.Ttl)
}

func (d *mockDiscoveryClient) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	var options discovery.Options
	err := options.Apply(opts...)
	if err != nil {
		return nil, err
	}

	return d.server.FindPeers(ns, options.Limit)
}

type dummyDiscovery struct{}

func (d *dummyDiscovery) Advertise(ctx context.Context, ns string, opts ...discovery.Option) (time.Duration, error) {
	return time.Hour, nil
}

func (d *dummyDiscovery) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	retCh := make(chan peer.AddrInfo)
	go func() {
		time.Sleep(time.Second)
		close(retCh)
	}()
	return retCh, nil
}

func TestSimpleDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup Discovery server and pubsub clients
	const numHosts = 20
	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}

	server := newDiscoveryServer()
	discOpts := []discovery.Option{discovery.Limit(numHosts), discovery.TTL(1 * time.Minute)}

	hosts := getNetHosts(t, ctx, numHosts)
	psubs := make([]*PubSub, numHosts)
	bitmaskHandlers := make([]*Bitmask, numHosts)

	for i, h := range hosts {
		disc := &mockDiscoveryClient{h, server}
		ps := getPubsub(ctx, h, WithDiscovery(disc, WithDiscoveryOpts(discOpts...)))
		psubs[i] = ps
		bitmaskHandlers[i], _ = ps.Join(bitmask)
	}

	// Subscribe with all but one pubsub instance
	msgs := make([]*Subscription, numHosts)
	for i, th := range bitmaskHandlers[1:] {
		subch, err := th.Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		msgs[i+1] = subch
	}

	// Wait for the advertisements to go through then check that they did
	for {
		server.mx.Lock()
		numPeers := len(server.db["floodsub:foobar"])
		server.mx.Unlock()
		if numPeers == numHosts-1 {
			break
		} else {
			time.Sleep(time.Millisecond * 100)
		}
	}

	for i, h := range hosts[1:] {
		if !server.hasPeerRecord("floodsub:"+string(bitmask), h.ID()) {
			t.Fatalf("Server did not register host %d with ID: %s", i+1, h.ID().Pretty())
		}
	}

	// Try subscribing followed by publishing a single message
	subch, err := bitmaskHandlers[0].Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	msgs[0] = subch

	msg := []byte("first message")
	if err := bitmaskHandlers[0].Publish(ctx, msg, WithReadiness(MinBitmaskSize(numHosts-1))); err != nil {
		t.Fatal(err)
	}

	for _, sub := range msgs {
		got, err := sub.Next(ctx)
		if err != nil {
			t.Fatal(sub.err)
		}
		if !bytes.Equal(msg, got.Data) {
			t.Fatal("got wrong message!")
		}
	}

	// Try random peers sending messages and make sure they are received
	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d the flooooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		if err := bitmaskHandlers[owner].Publish(ctx, msg, WithReadiness(MinBitmaskSize(1))); err != nil {
			t.Fatal(err)
		}

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubDiscoveryAfterBootstrap(t *testing.T) {
	t.Skip("flaky test disabled")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup Discovery server and pubsub clients
	partitionSize := BlossomSubDlo - 1
	numHosts := partitionSize * 2
	const ttl = 1 * time.Minute

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}

	server1, server2 := newDiscoveryServer(), newDiscoveryServer()
	discOpts := []discovery.Option{discovery.Limit(numHosts), discovery.TTL(ttl)}

	// Put the pubsub clients into two partitions
	hosts := getNetHosts(t, ctx, numHosts)
	psubs := make([]*PubSub, numHosts)
	bitmaskHandlers := make([]*Bitmask, numHosts)

	for i, h := range hosts {
		s := server1
		if i >= partitionSize {
			s = server2
		}
		disc := &mockDiscoveryClient{h, s}
		ps := getBlossomSub(ctx, h, WithDiscovery(disc, WithDiscoveryOpts(discOpts...)))
		psubs[i] = ps
		bitmaskHandlers[i], _ = ps.Join(bitmask)
	}

	msgs := make([]*Subscription, numHosts)
	for i, th := range bitmaskHandlers {
		subch, err := th.Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		msgs[i] = subch
	}

	// Wait for network to finish forming then join the partitions via discovery
	for _, ps := range psubs {
		waitUntilBlossomSubMeshCount(ps, bitmask, partitionSize-1)
	}

	for i := 0; i < partitionSize; i++ {
		if _, err := server1.Advertise("floodsub:"+string(bitmask), *host.InfoFromHost(hosts[i+partitionSize]), ttl); err != nil {
			t.Fatal(err)
		}
	}

	// test the mesh
	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(numHosts)

		if err := bitmaskHandlers[owner].Publish(ctx, msg, WithReadiness(MinBitmaskSize(numHosts-1))); err != nil {
			t.Fatal(err)
		}

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

//lint:ignore U1000 used only by skipped tests at present
func waitUntilBlossomSubMeshCount(ps *PubSub, bitmask []byte, count int) {
	done := false
	doneCh := make(chan bool, 1)
	rt := ps.rt.(*BlossomSubRouter)
	for !done {
		ps.eval <- func() {
			doneCh <- len(rt.mesh[string(bitmask)]) == count
		}
		done = <-doneCh
		if !done {
			time.Sleep(100 * time.Millisecond)
		}
	}
}
