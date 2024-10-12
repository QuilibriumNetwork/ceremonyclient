package blossomsub

import (
	"context"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
)

func TestBlossomSubConnTagMessageDeliveries(t *testing.T) {
	t.Skip("Test disabled with go-libp2p v0.22.0") // TODO: reenable test when updating to v0.23.0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldBlossomSubD := BlossomSubD
	oldBlossomSubDlo := BlossomSubDlo
	oldBlossomSubDHi := BlossomSubDhi
	oldBlossomSubConnTagDecayInterval := BlossomSubConnTagDecayInterval
	oldBlossomSubConnTagMessageDeliveryCap := BlossomSubConnTagMessageDeliveryCap

	// set the BlossomSub D parameters low, so that we have some peers outside the mesh
	BlossomSubDlo = 3
	BlossomSubD = 3
	BlossomSubDhi = 3
	// also set the tag decay interval so we don't have to wait forever for tests
	BlossomSubConnTagDecayInterval = time.Second

	// set the cap for deliveries above BlossomSubConnTagValueMeshPeer, so the sybils
	// will be forced out even if they end up in someone's mesh
	BlossomSubConnTagMessageDeliveryCap = 50

	// reset globals after test
	defer func() {
		BlossomSubD = oldBlossomSubD
		BlossomSubDlo = oldBlossomSubDlo
		BlossomSubDhi = oldBlossomSubDHi
		BlossomSubConnTagDecayInterval = oldBlossomSubConnTagDecayInterval
		BlossomSubConnTagMessageDeliveryCap = oldBlossomSubConnTagMessageDeliveryCap
	}()

	decayClock := clock.NewMock()
	decayCfg := connmgr.DecayerCfg{
		Resolution: time.Second,
		Clock:      decayClock,
	}

	nHonest := 5
	nSquatter := 10
	connLimit := 10

	connmgrs := make([]*connmgr.BasicConnMgr, nHonest)
	honestHosts := make([]host.Host, nHonest)
	honestPeers := make(map[peer.ID]struct{})

	for i := 0; i < nHonest; i++ {
		var err error
		connmgrs[i], err = connmgr.NewConnManager(nHonest, connLimit,
			connmgr.WithGracePeriod(0),
			connmgr.WithSilencePeriod(time.Millisecond),
			connmgr.DecayerConfig(&decayCfg),
		)
		if err != nil {
			t.Fatal(err)
		}

		h, err := libp2p.New(
			libp2p.ResourceManager(&network.NullResourceManager{}),
			libp2p.ConnectionManager(connmgrs[i]),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		honestHosts[i] = h
		honestPeers[h.ID()] = struct{}{}
	}

	// use flood publishing, so non-mesh peers will still be delivering messages
	// to everyone
	psubs := getBlossomSubs(ctx, honestHosts,
		WithFloodPublish(true))

	// sybil squatters to be connected later
	sybilHosts := getDefaultHosts(t, nSquatter)
	for _, h := range sybilHosts {
		squatter := &sybilSquatter{h: h}
		h.SetStreamHandler(BlossomSubID_v2, squatter.handleStream)
	}

	// connect the honest hosts
	connectAll(t, honestHosts)

	for _, h := range honestHosts {
		if len(h.Network().Conns()) < nHonest-1 {
			t.Errorf("expected to have conns to all honest peers, have %d", len(h.Network().Conns()))
		}
	}

	// subscribe everyone to the bitmask
	bitmask := []byte{0x00, 0x80, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// sleep to allow meshes to form
	time.Sleep(2 * time.Second)

	// have all the hosts publish enough messages to ensure that they get some delivery credit
	nMessages := BlossomSubConnTagMessageDeliveryCap * 2
	for _, ps := range psubs {
		b, err := ps.Join(bitmask)
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < nMessages; i++ {
			b[0].Publish(ctx, b[0].bitmask, []byte("hello"))
		}
	}

	// advance the fake time for the tag decay
	decayClock.Add(time.Second)

	// verify that they've given each other delivery connection tags
	tag := "pubsub-deliveries:" + string([]byte{0x00, 0x80, 0x00, 0x00})
	for _, h := range honestHosts {
		for _, h2 := range honestHosts {
			if h.ID() == h2.ID() {
				continue
			}
			val := getTagValue(h.ConnManager(), h2.ID(), tag)
			if val == 0 {
				t.Errorf("Expected non-zero delivery tag value for peer %s", h2.ID())
			}
		}
	}

	// now connect the sybils to put pressure on the real hosts' connection managers
	allHosts := honestHosts
	connectAll(t, allHosts)

	// verify that we have a bunch of connections
	for _, h := range honestHosts {
		if len(h.Network().Conns()) < nHonest-1 {
			t.Errorf("expected to have conns to all peers, have %d", len(h.Network().Conns()))
		}
	}

	// force the connection managers to trim, so we don't need to muck about with timing as much
	for _, cm := range connmgrs {
		cm.TrimOpenConns(ctx)
	}

	// we should still have conns to all the honest peers, but not the sybils
	for _, h := range honestHosts {
		nHonestConns := 0
		nDishonestConns := 0
		for _, conn := range h.Network().Conns() {
			if _, ok := honestPeers[conn.RemotePeer()]; !ok {
				nDishonestConns++
			} else {
				nHonestConns++
			}
		}
		if nDishonestConns > connLimit-nHonest {
			t.Errorf("expected most dishonest conns to be pruned, have %d", nDishonestConns)
		}
		if nHonestConns < nHonest-1 {
			t.Errorf("expected all honest conns to be preserved, have %d", nHonestConns)
		}
	}
}
