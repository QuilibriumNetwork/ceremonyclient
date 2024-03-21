package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"

	bhost "github.com/libp2p/go-libp2p/p2p/host/blank"
	swarmt "github.com/libp2p/go-libp2p/p2p/net/swarm/testing"

	"github.com/libp2p/go-msgio/protoio"
)

func getBlossomSub(ctx context.Context, h host.Host, opts ...Option) *PubSub {
	ps, err := NewBlossomSub(ctx, h, opts...)
	if err != nil {
		panic(err)
	}
	return ps
}

func getBlossomSubs(ctx context.Context, hs []host.Host, opts ...Option) []*PubSub {
	var psubs []*PubSub
	for _, h := range hs {
		psubs = append(psubs, getBlossomSub(ctx, h, opts...))
	}
	return psubs
}

func TestSparseBlossomSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	sparseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

func TestDenseBlossomSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

func TestBlossomSubFanout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs[1:] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

	// subscribe the owner
	subch, err := psubs[0].Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
	if err != nil {
		t.Fatal(err)
	}
	msgs = append(msgs, subch)

	// wait for a heartbeat
	time.Sleep(time.Second * 1)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

func TestBlossomSubFanoutMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs[1:] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

	// unsubscribe all peers to exercise fanout maintenance
	for _, sub := range msgs {
		sub.Cancel()
	}
	msgs = nil

	// wait for heartbeats
	time.Sleep(time.Second * 2)

	// resubscribe and repeat
	for _, ps := range psubs[1:] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

func TestBlossomSubFanoutExpiry(t *testing.T) {
	BlossomSubFanoutTTL = 1 * time.Second
	defer func() {
		BlossomSubFanoutTTL = 60 * time.Second
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 10)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs[1:] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

	psubs[0].eval <- func() {
		if len(psubs[0].rt.(*BlossomSubRouter).fanout) == 0 {
			t.Fatal("owner has no fanout")
		}
	}

	// wait for TTL to expire fanout peers in owner
	time.Sleep(time.Second * 2)

	psubs[0].eval <- func() {
		if len(psubs[0].rt.(*BlossomSubRouter).fanout) > 0 {
			t.Fatal("fanout hasn't expired")
		}
	}

	// wait for it to run in the event loop
	time.Sleep(10 * time.Millisecond)
}

func TestBlossomSubGossip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}

		// wait a bit to have some gossip interleaved
		time.Sleep(time.Millisecond * 100)
	}

	// and wait for some gossip flushing
	time.Sleep(time.Second * 2)
}

func TestBlossomSubGossipPiggyback(t *testing.T) {
	t.Skip("test no longer relevant; gossip propagation has become eager")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	var xmsgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xba, 0x2c, 0x12, 0x08})
		if err != nil {
			t.Fatal(err)
		}

		xmsgs = append(xmsgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)
		psubs[owner].Publish([]byte{0xba, 0x2c, 0x12, 0x08}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}

		for _, sub := range xmsgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}

		// wait a bit to have some gossip interleaved
		time.Sleep(time.Millisecond * 100)
	}

	// and wait for some gossip flushing
	time.Sleep(time.Second * 2)
}

func TestBlossomSubGossipPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts)

	hosts1 := hosts[:BlossomSubD+1]
	hosts2 := append(hosts[BlossomSubD+1:], hosts[0])

	denseConnect(t, hosts1)
	denseConnect(t, hosts2)

	var msgs1 []*Subscription
	for _, ps := range psubs[1 : BlossomSubD+1] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs1 = append(msgs1, subch)
	}

	time.Sleep(time.Second * 1)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 0

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

		for _, sub := range msgs1 {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}

	time.Sleep(time.Millisecond * 100)

	var msgs2 []*Subscription
	for _, ps := range psubs[BlossomSubD+1:] {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs2 = append(msgs2, subch)
	}

	var collect [][]byte
	for i := 0; i < 10; i++ {
		for _, sub := range msgs2 {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			collect = append(collect, got.Data)
		}
	}

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))
		gotit := false
		for j := 0; j < len(collect); j++ {
			if bytes.Equal(msg, collect[j]) {
				gotit = true
				break
			}
		}
		if !gotit {
			t.Fatalf("Didn't get message %s", string(msg))
		}
	}
}

func TestBlossomSubPrune(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// disconnect some peers from the mesh to get some PRUNEs
	for _, sub := range msgs[:5] {
		sub.Cancel()
	}

	// wait a bit to take effect
	time.Sleep(time.Millisecond * 100)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

		for _, sub := range msgs[5:] {
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

func TestBlossomSubPruneBackoffTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 10)

	// App specific score that we'll change later.
	currentScoreForHost0 := int32(0)

	params := DefaultBlossomSubParams()
	params.HeartbeatInitialDelay = time.Millisecond * 10
	params.HeartbeatInterval = time.Millisecond * 100

	psubs := getBlossomSubs(ctx, hosts, WithBlossomSubParams(params), WithPeerScore(
		&PeerScoreParams{
			AppSpecificScore: func(p peer.ID) float64 {
				if p == hosts[0].ID() {
					return float64(atomic.LoadInt32(&currentScoreForHost0))
				} else {
					return 0
				}
			},
			AppSpecificWeight: 1,
			DecayInterval:     time.Second,
			DecayToZero:       0.01,
		},
		&PeerScoreThresholds{
			GossipThreshold:   -1,
			PublishThreshold:  -1,
			GraylistThreshold: -1,
		}))

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	connectAll(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second)

	pruneTime := time.Now()
	// Flip the score. Host 0 should be pruned from everyone
	atomic.StoreInt32(&currentScoreForHost0, -1000)

	// wait for heartbeats to run and prune
	time.Sleep(time.Second)

	wg := sync.WaitGroup{}
	var missingBackoffs uint32 = 0
	for i := 1; i < 10; i++ {
		wg.Add(1)
		// Copy i so this func keeps the correct value in the closure.
		var idx = i
		// Run this check in the eval thunk so that we don't step over the heartbeat goroutine and trigger a race.
		psubs[idx].rt.(*BlossomSubRouter).p.eval <- func() {
			defer wg.Done()
			backoff, ok := psubs[idx].rt.(*BlossomSubRouter).backoff[string([]byte{0xf0, 0x0b, 0xa1, 0x20})][hosts[0].ID()]
			if !ok {
				atomic.AddUint32(&missingBackoffs, 1)
			}
			if ok && backoff.Sub(pruneTime)-params.PruneBackoff > time.Second {
				t.Errorf("backoff time should be equal to prune backoff (with some slack) was %v", backoff.Sub(pruneTime)-params.PruneBackoff)
			}
		}
	}
	wg.Wait()

	// Sometimes not all the peers will have updated their backoffs by this point. If the majority haven't we'll fail this test.
	if missingBackoffs >= 5 {
		t.Errorf("missing too many backoffs: %v", missingBackoffs)
	}

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		// Don't publish from host 0, since everyone should have pruned it.
		owner := rand.Intn(len(psubs)-1) + 1

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

		for _, sub := range msgs[1:] {
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

func TestBlossomSubGraft(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	sparseConnect(t, hosts)

	time.Sleep(time.Second * 1)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)

		// wait for announce to propagate
		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second * 1)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

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

func TestBlossomSubRemovePeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x20})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// disconnect some peers to exercise RemovePeer paths
	for _, host := range hosts[:5] {
		host.Close()
	}

	// wait a heartbeat
	time.Sleep(time.Second * 1)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 5 + rand.Intn(len(psubs)-5)

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x20}, msg)

		for _, sub := range msgs[5:] {
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

func TestBlossomSubGraftPruneRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 10)
	psubs := getBlossomSubs(ctx, hosts)
	denseConnect(t, hosts)

	var bitmasks [][]byte
	var msgs [][]*Subscription
	for i := 0; i < 35; i++ {
		bitmask := []byte{byte(i)}
		bitmasks = append(bitmasks, bitmask)

		var subs []*Subscription
		for _, ps := range psubs {
			subch, err := ps.Subscribe(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, subch)
		}
		msgs = append(msgs, subs)
	}

	// wait for heartbeats to build meshes
	time.Sleep(time.Second * 5)

	for i, bitmask := range bitmasks {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish(bitmask, msg)

		for _, sub := range msgs[i] {
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

func TestBlossomSubControlPiggyback(t *testing.T) {
	t.Skip("travis regularly fails on this test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 10)
	psubs := getBlossomSubs(ctx, hosts)
	denseConnect(t, hosts)

	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xff, 0xff, 0xff, 0xff})
		if err != nil {
			t.Fatal(err)
		}
		go func(sub *Subscription) {
			for {
				_, err := sub.Next(ctx)
				if err != nil {
					break
				}
			}
		}(subch)
	}

	time.Sleep(time.Second * 1)

	// create a background flood of messages that overloads the queues
	done := make(chan struct{})
	go func() {
		owner := rand.Intn(len(psubs))
		for i := 0; i < 10000; i++ {
			msg := []byte("background flooooood")
			psubs[owner].Publish([]byte{0xff, 0xff, 0xff, 0xff}, msg)
		}
		done <- struct{}{}
	}()

	time.Sleep(time.Millisecond * 20)

	// and subscribe to a bunch of bitmasks in the meantime -- this should
	// result in some dropped control messages, with subsequent piggybacking
	// in the background flood
	var bitmasks [][]byte
	var msgs [][]*Subscription
	for i := 0; i < 5; i++ {
		bitmask := []byte{byte(i)}
		bitmasks = append(bitmasks, bitmask)

		var subs []*Subscription
		for _, ps := range psubs {
			subch, err := ps.Subscribe(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, subch)
		}
		msgs = append(msgs, subs)
	}

	// wait for the flood to stop
	<-done

	// and test that we have functional overlays
	for i, bitmask := range bitmasks {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish(bitmask, msg)

		for _, sub := range msgs[i] {
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

func TestMixedBlossomSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 30)

	gsubs := getBlossomSubs(ctx, hosts[:20])
	fsubs := getPubsubs(ctx, hosts[20:])
	psubs := append(gsubs, fsubs...)

	var msgs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x2b})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	sparseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish([]byte{0xf0, 0x0b, 0xa1, 0x2b}, msg)

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

func TestBlossomSubMultihops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 6)

	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[2], hosts[3])
	connect(t, hosts[3], hosts[4])
	connect(t, hosts[4], hosts[5])

	var subs []*Subscription
	for i := 1; i < 6; i++ {
		ch, err := psubs[i].Subscribe([]byte{0xf0, 0x0b, 0xa1, 0x2b})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, ch)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	msg := []byte("i like cats")
	err := psubs[0].Publish([]byte{0xf0, 0x0b, 0xa1, 0x2b}, msg)
	if err != nil {
		t.Fatal(err)
	}

	// last node in the chain should get the message
	select {
	case out := <-subs[4].ch:
		if !bytes.Equal(out.GetData(), msg) {
			t.Fatal("got wrong data")
		}
	case <-time.After(time.Second * 5):
		t.Fatal("timed out waiting for message")
	}
}

func TestBlossomSubTreeTopology(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 10)
	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[1], hosts[4])
	connect(t, hosts[2], hosts[3])
	connect(t, hosts[0], hosts[5])
	connect(t, hosts[5], hosts[6])
	connect(t, hosts[5], hosts[8])
	connect(t, hosts[6], hosts[7])
	connect(t, hosts[8], hosts[9])

	/*
		[0] -> [1] -> [2] -> [3]
		 |      L->[4]
		 v
		[5] -> [6] -> [7]
		 |
		 v
		[8] -> [9]
	*/

	var chs []*Subscription
	for _, ps := range psubs {
		ch, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}

		chs = append(chs, ch)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	assertPeerLists(t, hosts, psubs[0], 1, 5)
	assertPeerLists(t, hosts, psubs[1], 0, 2, 4)
	assertPeerLists(t, hosts, psubs[2], 1, 3)

	checkMessageRouting(t, []byte{0xf1, 0x22, 0xb0, 0x22}, []*PubSub{psubs[9], psubs[3]}, chs)
}

// this tests overlay bootstrapping through px in BlossomSub v1.2
// we start with a star topology and rely on px through prune to build the mesh
func TestBlossomSubStarTopology(t *testing.T) {
	originalBlossomSubD := BlossomSubD
	BlossomSubD = 4
	originalBlossomSubDhi := BlossomSubDhi
	BlossomSubDhi = BlossomSubD + 1
	originalBlossomSubDlo := BlossomSubDlo
	BlossomSubDlo = BlossomSubD - 1
	originalBlossomSubDscore := BlossomSubDscore
	BlossomSubDscore = BlossomSubDlo
	defer func() {
		BlossomSubD = originalBlossomSubD
		BlossomSubDhi = originalBlossomSubDhi
		BlossomSubDlo = originalBlossomSubDlo
		BlossomSubDscore = originalBlossomSubDscore
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts, WithPeerExchange(true), WithFloodPublish(true))

	// configure the center of the star with a very low D
	psubs[0].eval <- func() {
		gs := psubs[0].rt.(*BlossomSubRouter)
		gs.params.D = 0
		gs.params.Dlo = 0
		gs.params.Dhi = 0
		gs.params.Dscore = 0
	}

	// add all peer addresses to the peerstores
	// this is necessary because we can't have signed address records witout identify
	// pushing them
	for i := range hosts {
		for j := range hosts {
			if i == j {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hosts[j].ID(), hosts[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	time.Sleep(time.Second)

	// build the mesh
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	// wait a bit for the mesh to build
	time.Sleep(10 * time.Second)

	// check that all peers have > 1 connection
	for i, h := range hosts {
		if len(h.Network().Conns()) == 1 {
			t.Errorf("peer %d has ony a single connection", i)
		}
	}

	// send a message from each peer and assert it was propagated
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

// this tests overlay bootstrapping through px in BlossomSub v1.2, with addresses
// exchanged in signed peer records.
// we start with a star topology and rely on px through prune to build the mesh
func TestBlossomSubStarTopologyWithSignedPeerRecords(t *testing.T) {
	originalBlossomSubD := BlossomSubD
	BlossomSubD = 4
	originalBlossomSubDhi := BlossomSubDhi
	BlossomSubDhi = BlossomSubD + 1
	originalBlossomSubDlo := BlossomSubDlo
	BlossomSubDlo = BlossomSubD - 1
	originalBlossomSubDscore := BlossomSubDscore
	BlossomSubDscore = BlossomSubDlo
	defer func() {
		BlossomSubD = originalBlossomSubD
		BlossomSubDhi = originalBlossomSubDhi
		BlossomSubDlo = originalBlossomSubDlo
		BlossomSubDscore = originalBlossomSubDscore
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts, WithPeerExchange(true), WithFloodPublish(true))

	// configure the center of the star with a very low D
	psubs[0].eval <- func() {
		gs := psubs[0].rt.(*BlossomSubRouter)
		gs.params.D = 0
		gs.params.Dlo = 0
		gs.params.Dhi = 0
		gs.params.Dscore = 0
	}

	// manually create signed peer records for each host and add them to the
	// peerstore of the center of the star, which is doing the bootstrapping
	for i := range hosts[1:] {
		privKey := hosts[i].Peerstore().PrivKey(hosts[i].ID())
		if privKey == nil {
			t.Fatalf("unable to get private key for host %s", hosts[i].ID().Pretty())
		}
		ai := host.InfoFromHost(hosts[i])
		rec := peer.PeerRecordFromAddrInfo(*ai)
		signedRec, err := record.Seal(rec, privKey)
		if err != nil {
			t.Fatalf("error creating signed peer record: %s", err)
		}

		cab, ok := peerstore.GetCertifiedAddrBook(hosts[0].Peerstore())
		if !ok {
			t.Fatal("peerstore does not implement CertifiedAddrBook")
		}
		_, err = cab.ConsumePeerRecord(signedRec, peerstore.PermanentAddrTTL)
		if err != nil {
			t.Fatalf("error adding signed peer record: %s", err)
		}
	}

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	time.Sleep(time.Second)

	// build the mesh
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	// wait a bit for the mesh to build
	time.Sleep(10 * time.Second)

	// check that all peers have > 1 connection
	for i, h := range hosts {
		if len(h.Network().Conns()) == 1 {
			t.Errorf("peer %d has ony a single connection", i)
		}
	}

	// send a message from each peer and assert it was propagated
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubDirectPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getNetHosts(t, ctx, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0], WithDirectConnectTicks(2)),
		getBlossomSub(ctx, h[1], WithDirectPeers([]peer.AddrInfo{{ID: h[2].ID(), Addrs: h[2].Addrs()}}), WithDirectConnectTicks(2)),
		getBlossomSub(ctx, h[2], WithDirectPeers([]peer.AddrInfo{{ID: h[1].ID(), Addrs: h[1].Addrs()}}), WithDirectConnectTicks(2)),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// verify that the direct peers connected
	time.Sleep(2 * time.Second)
	if len(h[1].Network().ConnsToPeer(h[2].ID())) == 0 {
		t.Fatal("expected a connection between direct peers")
	}

	// build the mesh
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// publish some messages
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}

	// disconnect the direct peers to test reconnection
	for _, c := range h[1].Network().ConnsToPeer(h[2].ID()) {
		c.Close()
	}

	time.Sleep(5 * time.Second)

	if len(h[1].Network().ConnsToPeer(h[2].ID())) == 0 {
		t.Fatal("expected a connection between direct peers")
	}

	// publish some messages
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubPeerFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getNetHosts(t, ctx, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0], WithPeerFilter(func(pid peer.ID, bitmask []byte) bool {
			return pid == h[1].ID()
		})),
		getBlossomSub(ctx, h[1], WithPeerFilter(func(pid peer.ID, bitmask []byte) bool {
			return pid == h[0].ID()
		})),
		getBlossomSub(ctx, h[2]),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// Join all peers
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	msg := []byte("message")

	psubs[0].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
	assertReceive(t, subs[1], msg)
	assertNeverReceives(t, subs[2], time.Second)

	psubs[1].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
	assertReceive(t, subs[0], msg)
	assertNeverReceives(t, subs[2], time.Second)
}

func TestBlossomSubDirectPeersFanout(t *testing.T) {
	// regression test for #371
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getNetHosts(t, ctx, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1], WithDirectPeers([]peer.AddrInfo{{ID: h[2].ID(), Addrs: h[2].Addrs()}})),
		getBlossomSub(ctx, h[2], WithDirectPeers([]peer.AddrInfo{{ID: h[1].ID(), Addrs: h[1].Addrs()}})),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// Join all peers except h2
	var subs []*Subscription
	for _, ps := range psubs[:2] {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// h2 publishes some messages to build a fanout
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[2].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}

	// verify that h0 is in the fanout of h2, but not h1 who is a direct peer
	result := make(chan bool, 2)
	psubs[2].eval <- func() {
		rt := psubs[2].rt.(*BlossomSubRouter)
		fanout := rt.fanout[string([]byte{0xf1, 0x22, 0xb0, 0x22})]
		_, ok := fanout[h[0].ID()]
		result <- ok
		_, ok = fanout[h[1].ID()]
		result <- ok
	}

	inFanout := <-result
	if !inFanout {
		t.Fatal("expected peer 0 to be in fanout")
	}

	inFanout = <-result
	if inFanout {
		t.Fatal("expected peer 1 to not be in fanout")
	}

	// now subscribe h2 too and verify tht h0 is in the mesh but not h1
	_, err := psubs[2].Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	psubs[2].eval <- func() {
		rt := psubs[2].rt.(*BlossomSubRouter)
		mesh := rt.mesh[string([]byte{0xf1, 0x22, 0xb0, 0x22})]
		_, ok := mesh[h[0].ID()]
		result <- ok
		_, ok = mesh[h[1].ID()]
		result <- ok
	}

	inMesh := <-result
	if !inMesh {
		t.Fatal("expected peer 0 to be in mesh")
	}

	inMesh = <-result
	if inMesh {
		t.Fatal("expected peer 1 to not be in mesh")
	}
}

func TestBlossomSubFloodPublish(t *testing.T) {
	// uses a star topology without PX and publishes from the star to verify that all
	// messages get received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts, WithFloodPublish(true))

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	// build the (partial, unstable) mesh
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// send a message from the star and assert it was received
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[0].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubEnoughPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts)

	for _, ps := range psubs {
		_, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
	}

	// at this point we have no connections and no mesh, so EnoughPeers should return false
	res := make(chan bool, 1)
	psubs[0].eval <- func() {
		res <- psubs[0].rt.EnoughPeers([]byte{0xf1, 0x22, 0xb0, 0x22}, 0)
	}
	enough := <-res
	if enough {
		t.Fatal("should not have enough peers")
	}

	// connect them densly to build up the mesh
	denseConnect(t, hosts)

	time.Sleep(3 * time.Second)

	psubs[0].eval <- func() {
		res <- psubs[0].rt.EnoughPeers([]byte{0xf1, 0x22, 0xb0, 0x22}, 0)
	}
	enough = <-res
	if !enough {
		t.Fatal("should have enough peers")
	}
}

func TestBlossomSubCustomParams(t *testing.T) {
	// in this test we score sinkhole a peer to exercise code paths relative to negative scores
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params := DefaultBlossomSubParams()

	wantedFollowTime := 1 * time.Second
	params.IWantFollowupTime = wantedFollowTime

	customGossipFactor := 0.12
	params.GossipFactor = customGossipFactor

	wantedMaxPendingConns := 23
	params.MaxPendingConnections = wantedMaxPendingConns
	hosts := getNetHosts(t, ctx, 1)
	psubs := getBlossomSubs(ctx, hosts,
		WithBlossomSubParams(params))

	if len(psubs) != 1 {
		t.Fatalf("incorrect number of pusbub objects received: wanted %d but got %d", 1, len(psubs))
	}

	rt, ok := psubs[0].rt.(*BlossomSubRouter)
	if !ok {
		t.Fatal("Did not get gossip sub router from pub sub object")
	}

	if rt.params.IWantFollowupTime != wantedFollowTime {
		t.Errorf("Wanted %d of param BlossomSubIWantFollowupTime but got %d", wantedFollowTime, rt.params.IWantFollowupTime)
	}
	if rt.params.GossipFactor != customGossipFactor {
		t.Errorf("Wanted %f of param BlossomSubGossipFactor but got %f", customGossipFactor, rt.params.GossipFactor)
	}
	if rt.params.MaxPendingConnections != wantedMaxPendingConns {
		t.Errorf("Wanted %d of param BlossomSubMaxPendingConnections but got %d", wantedMaxPendingConns, rt.params.MaxPendingConnections)
	}
}

func TestBlossomSubNegativeScore(t *testing.T) {
	// in this test we score sinkhole a peer to exercise code paths relative to negative scores
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 20)
	psubs := getBlossomSubs(ctx, hosts,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore: func(p peer.ID) float64 {
					if p == hosts[0].ID() {
						return -1000
					} else {
						return 0
					}
				},
				AppSpecificWeight: 1,
				DecayInterval:     time.Second,
				DecayToZero:       0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -10,
				PublishThreshold:  -100,
				GraylistThreshold: -10000,
			}))

	denseConnect(t, hosts)

	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(3 * time.Second)

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i%20].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// let the sinkholed peer try to emit gossip as well
	time.Sleep(2 * time.Second)

	// checks:
	// 1. peer 0 should only receive its own message
	// 2. peers 1-20 should not receive a message from peer 0, because it's not part of the mesh
	//    and its gossip is rejected
	collectAll := func(sub *Subscription) []*Message {
		var res []*Message
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				break
			}

			res = append(res, msg)
		}

		return res
	}

	count := len(collectAll(subs[0]))
	if count != 1 {
		t.Fatalf("expected 1 message but got %d instead", count)
	}

	for _, sub := range subs[1:] {
		all := collectAll(sub)
		for _, m := range all {
			if m.ReceivedFrom == hosts[0].ID() {
				t.Fatal("received message from sinkholed peer")
			}
		}
	}
}

func TestBlossomSubScoreValidatorEx(t *testing.T) {
	// this is a test that of the two message drop responses from a validator
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 3)
	psubs := getBlossomSubs(ctx, hosts,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore: func(p peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0xf1, 0x22, 0xb0, 0x22}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
			},
			&PeerScoreThresholds{
				GossipThreshold:   -10,
				PublishThreshold:  -100,
				GraylistThreshold: -10000,
			}))

	connectAll(t, hosts)

	err := psubs[0].RegisterBitmaskValidator([]byte{0xf1, 0x22, 0xb0, 0x22}, func(ctx context.Context, p peer.ID, msg *Message) ValidationResult {
		// we ignore host1 and reject host2
		if p == hosts[1].ID() {
			return ValidationIgnore
		}
		if p == hosts[2].ID() {
			return ValidationReject
		}

		return ValidationAccept
	})
	if err != nil {
		t.Fatal(err)
	}

	sub, err := psubs[0].Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	expectNoMessage := func(sub *Subscription) {
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		m, err := sub.Next(ctx)
		if err == nil {
			t.Fatal("expected no message, but got ", string(m.Data))
		}
	}

	psubs[1].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, []byte("i am not a walrus"))
	psubs[2].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, []byte("i am not a walrus either"))

	// assert no messages
	expectNoMessage(sub)

	// assert that peer1's score is still 0 (its message was ignored) while peer2 should have
	// a negative score (its message got rejected)
	res := make(chan float64, 1)
	psubs[0].eval <- func() {
		res <- psubs[0].rt.(*BlossomSubRouter).score.Score(hosts[1].ID())
	}
	score := <-res
	if score != 0 {
		t.Fatalf("expected 0 score for peer1, but got %f", score)
	}

	psubs[0].eval <- func() {
		res <- psubs[0].rt.(*BlossomSubRouter).score.Score(hosts[2].ID())
	}
	score = <-res
	if score >= 0 {
		t.Fatalf("expected negative score for peer2, but got %f", score)
	}
}

func TestBlossomSubPiggybackControl(t *testing.T) {
	// this is a direct test of the piggybackControl function as we can't reliably
	// trigger it on travis
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := bhost.NewBlankHost(swarmt.GenSwarm(t))
	defer h.Close()
	ps := getBlossomSub(ctx, h)

	blah := peer.ID("bogotr0n")

	res := make(chan *RPC, 1)
	ps.eval <- func() {
		gs := ps.rt.(*BlossomSubRouter)
		test1 := []byte{0xff, 0x00, 0x00, 0x00}
		test2 := []byte{0x00, 0xff, 0x00, 0x00}
		test3 := []byte{0x00, 0x00, 0xff, 0x00}
		gs.mesh[string(test1)] = make(map[peer.ID]struct{})
		gs.mesh[string(test2)] = make(map[peer.ID]struct{})
		gs.mesh[string(test1)][blah] = struct{}{}

		rpc := &RPC{RPC: pb.RPC{}}
		gs.piggybackControl(blah, rpc, &pb.ControlMessage{
			Graft: []*pb.ControlGraft{{Bitmask: test1}, {Bitmask: test2}, {Bitmask: test3}},
			Prune: []*pb.ControlPrune{{Bitmask: test1}, {Bitmask: test2}, {Bitmask: test3}},
		})
		res <- rpc
	}

	rpc := <-res
	if rpc.Control == nil {
		t.Fatal("expected non-nil control message")
	}
	if len(rpc.Control.Graft) != 1 {
		t.Fatal("expected 1 GRAFT")
	}
	if !bytes.Equal(rpc.Control.Graft[0].GetBitmask(), []byte{0xff, 0x00, 0x00, 0x00}) {
		t.Fatal("expected test1 as graft bitmask ID")
	}
	if len(rpc.Control.Prune) != 2 {
		t.Fatal("expected 2 PRUNEs")
	}
	if !bytes.Equal(rpc.Control.Prune[0].GetBitmask(), []byte{0x00, 0xff, 0x00, 0x00}) {
		t.Fatal("expected test2 as prune bitmask ID")
	}
	if !bytes.Equal(rpc.Control.Prune[1].GetBitmask(), []byte{0x00, 0x00, 0xff, 0x00}) {
		t.Fatal("expected test3 as prune bitmask ID")
	}
}

func TestBlossomSubMultipleGraftBitmasks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 2)
	psubs := getBlossomSubs(ctx, hosts)
	sparseConnect(t, hosts)

	time.Sleep(time.Second * 1)

	firstBitmask := []byte{0xff, 0x00, 0x00, 0x00}
	secondBitmask := []byte{0x00, 0xff, 0x00, 0x00}
	thirdBitmask := []byte{0x00, 0x00, 0xff, 0x00}

	firstPeer := hosts[0].ID()
	secondPeer := hosts[1].ID()

	p2Sub := psubs[1]
	p1Router := psubs[0].rt.(*BlossomSubRouter)
	p2Router := psubs[1].rt.(*BlossomSubRouter)

	finChan := make(chan struct{})

	p2Sub.eval <- func() {
		// Add bitmasks to second peer
		p2Router.mesh[string(firstBitmask)] = map[peer.ID]struct{}{}
		p2Router.mesh[string(secondBitmask)] = map[peer.ID]struct{}{}
		p2Router.mesh[string(thirdBitmask)] = map[peer.ID]struct{}{}

		finChan <- struct{}{}
	}
	<-finChan

	// Send multiple GRAFT messages to second peer from
	// 1st peer
	p1Router.sendGraftPrune(map[peer.ID][][]byte{
		secondPeer: {firstBitmask, secondBitmask, thirdBitmask},
	}, map[peer.ID][][]byte{}, map[peer.ID]bool{})

	time.Sleep(time.Second * 1)

	p2Sub.eval <- func() {
		if _, ok := p2Router.mesh[string(firstBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", firstBitmask)
		}
		if _, ok := p2Router.mesh[string(secondBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", secondBitmask)
		}
		if _, ok := p2Router.mesh[string(thirdBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", thirdBitmask)
		}
		finChan <- struct{}{}
	}
	<-finChan
}

func TestBlossomSubOpportunisticGrafting(t *testing.T) {
	originalBlossomSubPruneBackoff := BlossomSubPruneBackoff
	BlossomSubPruneBackoff = 500 * time.Millisecond
	originalBlossomSubGraftFloodThreshold := BlossomSubGraftFloodThreshold
	BlossomSubGraftFloodThreshold = 100 * time.Millisecond
	originalBlossomSubOpportunisticGraftTicks := BlossomSubOpportunisticGraftTicks
	BlossomSubOpportunisticGraftTicks = 2
	defer func() {
		BlossomSubPruneBackoff = originalBlossomSubPruneBackoff
		BlossomSubGraftFloodThreshold = originalBlossomSubGraftFloodThreshold
		BlossomSubOpportunisticGraftTicks = originalBlossomSubOpportunisticGraftTicks
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 50)
	// pubsubs for the first 10 hosts
	psubs := getBlossomSubs(ctx, hosts[:10],
		WithFloodPublish(true),
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore:  func(peer.ID) float64 { return 0 },
				AppSpecificWeight: 0,
				DecayInterval:     time.Second,
				DecayToZero:       0.01,
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0xf1, 0x22, 0xb0, 0x22}): {
						BitmaskWeight:                 1,
						TimeInMeshWeight:              0.0002777,
						TimeInMeshQuantum:             time.Second,
						TimeInMeshCap:                 3600,
						FirstMessageDeliveriesWeight:  1,
						FirstMessageDeliveriesDecay:   0.9997,
						FirstMessageDeliveriesCap:     100,
						InvalidMessageDeliveriesDecay: 0.99997,
					},
				},
			},
			&PeerScoreThresholds{
				GossipThreshold:             -10,
				PublishThreshold:            -100,
				GraylistThreshold:           -10000,
				OpportunisticGraftThreshold: 1,
			}))

	// connect the real hosts with degree 5
	connectSome(t, hosts[:10], 5)

	// sybil squatters for the remaining 40 hosts
	for _, h := range hosts[10:] {
		squatter := &sybilSquatter{h: h}
		h.SetStreamHandler(BlossomSubID_v12, squatter.handleStream)
	}

	// connect all squatters to every real host
	for _, squatter := range hosts[10:] {
		for _, real := range hosts[:10] {
			connect(t, squatter, real)
		}
	}

	// wait a bit for the connections to propagate events to the pubsubs
	time.Sleep(time.Second)

	// ask the real pubsus to join the bitmask
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		// consume the messages
		go func(sub *Subscription) {
			for {
				_, err := sub.Next(ctx)
				if err != nil {
					return
				}
			}
		}(sub)
	}

	// publish a bunch of messages from the real hosts
	for i := 0; i < 1000; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i%10].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// now wait a few of oppgraft cycles
	time.Sleep(7 * time.Second)

	// check the honest peer meshes, they should have at least 3 honest peers each
	res := make(chan int, 1)
	for _, ps := range psubs {
		ps.eval <- func() {
			gs := ps.rt.(*BlossomSubRouter)
			count := 0
			for _, h := range hosts[:10] {
				_, ok := gs.mesh[string([]byte{0xf1, 0x22, 0xb0, 0x22})][h.ID()]
				if ok {
					count++
				}
			}
			res <- count
		}

		count := <-res
		if count < 3 {
			t.Fatalf("expected at least 3 honest peers, got %d", count)
		}
	}
}
func TestBlossomSubLeaveBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getNetHosts(t, ctx, 2)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1]),
	}

	connect(t, h[0], h[1])

	// Join all peers
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	leaveTime := time.Now()
	done := make(chan struct{})

	psubs[0].rt.(*BlossomSubRouter).p.eval <- func() {
		defer close(done)
		psubs[0].rt.Leave([]byte{0xf1, 0x22, 0xb0, 0x22})
		time.Sleep(time.Second)
		peerMap := psubs[0].rt.(*BlossomSubRouter).backoff[string([]byte{0xf1, 0x22, 0xb0, 0x22})]
		if len(peerMap) != 1 {
			t.Fatalf("No peer is populated in the backoff map for peer 0")
		}
		_, ok := peerMap[h[1].ID()]
		if !ok {
			t.Errorf("Expected peer does not exist in the backoff map")
		}

		backoffTime := peerMap[h[1].ID()].Sub(leaveTime)
		// Check that the backoff time is roughly the unsubscribebackoff time (with a slack of 1s)
		if backoffTime-BlossomSubUnsubscribeBackoff > time.Second {
			t.Error("Backoff time should be set to BlossomSubUnsubscribeBackoff.")
		}
	}
	<-done

	done = make(chan struct{})
	// Ensure that remote peer 1 also applies the backoff appropriately
	// for peer 0.
	psubs[1].rt.(*BlossomSubRouter).p.eval <- func() {
		defer close(done)
		peerMap2 := psubs[1].rt.(*BlossomSubRouter).backoff[string([]byte{0xf1, 0x22, 0xb0, 0x22})]
		if len(peerMap2) != 1 {
			t.Fatalf("No peer is populated in the backoff map for peer 1")
		}
		_, ok := peerMap2[h[0].ID()]
		if !ok {
			t.Errorf("Expected peer does not exist in the backoff map")
		}

		backoffTime := peerMap2[h[0].ID()].Sub(leaveTime)
		// Check that the backoff time is roughly the unsubscribebackoff time (with a slack of 1s)
		if backoffTime-BlossomSubUnsubscribeBackoff > time.Second {
			t.Error("Backoff time should be set to BlossomSubUnsubscribeBackoff.")
		}
	}
	<-done
}

func TestBlossomSubJoinBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getNetHosts(t, ctx, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1]),
		getBlossomSub(ctx, h[2]),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	router0 := psubs[0].rt.(*BlossomSubRouter)

	// Add in backoff for peer.
	peerMap := make(map[peer.ID]time.Time)
	peerMap[h[1].ID()] = time.Now().Add(router0.params.UnsubscribeBackoff)

	router0.backoff[string([]byte{0xf1, 0x22, 0xb0, 0x22})] = peerMap

	// Join all peers
	var subs []*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	meshMap := router0.mesh[string([]byte{0xf1, 0x22, 0xb0, 0x22})]
	if len(meshMap) != 1 {
		t.Fatalf("Unexpect peer included in the mesh")
	}

	_, ok := meshMap[h[1].ID()]
	if ok {
		t.Fatalf("Peer that was to be backed off is included in the mesh")
	}
}

type sybilSquatter struct {
	h host.Host
}

func (sq *sybilSquatter) handleStream(s network.Stream) {
	defer s.Close()

	os, err := sq.h.NewStream(context.Background(), s.Conn().RemotePeer(), BlossomSubID_v12)
	if err != nil {
		panic(err)
	}

	// send a subscription for test in the output stream to become candidate for GRAFT
	// and then just read and ignore the incoming RPCs
	r := protoio.NewDelimitedReader(s, 1<<20)
	w := protoio.NewDelimitedWriter(os)
	truth := true
	bitmask := []byte{0xf1, 0x22, 0xb0, 0x22}
	err = w.WriteMsg(&pb.RPC{Subscriptions: []*pb.RPC_SubOpts{{Subscribe: truth, Bitmask: bitmask}}})
	if err != nil {
		panic(err)
	}

	var rpc pb.RPC
	for {
		rpc.Reset()
		err = r.ReadMsg(&rpc)
		if err != nil {
			if err != io.EOF {
				s.Reset()
			}
			return
		}
	}
}

func TestBlossomSubPeerScoreInspect(t *testing.T) {
	// this test exercises the code path sof peer score inspection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 2)

	inspector := &mockPeerScoreInspector{}
	psub1 := getBlossomSub(ctx, hosts[0],
		WithPeerScore(
			&PeerScoreParams{
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0xf1, 0x22, 0xb0, 0x22}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						FirstMessageDeliveriesWeight:   1,
						FirstMessageDeliveriesDecay:    0.999,
						FirstMessageDeliveriesCap:      100,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
				AppSpecificScore: func(peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -1,
				PublishThreshold:  -10,
				GraylistThreshold: -1000,
			}),
		WithPeerScoreInspect(inspector.inspect, time.Second))
	psub2 := getBlossomSub(ctx, hosts[1])
	psubs := []*PubSub{psub1, psub2}

	connect(t, hosts[0], hosts[1])

	for _, ps := range psubs {
		_, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(time.Second)

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[i%2].Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(time.Second + 200*time.Millisecond)

	score2 := inspector.score(hosts[1].ID())
	if score2 < 9 {
		t.Fatalf("expected score to be at least 9, instead got %f", score2)
	}
}

func TestBlossomSubPeerScoreResetBitmaskParams(t *testing.T) {
	// this test exercises the code path sof peer score inspection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 1)

	ps := getBlossomSub(ctx, hosts[0],
		WithPeerScore(
			&PeerScoreParams{
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0xf1, 0x22, 0xb0, 0x22}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						FirstMessageDeliveriesWeight:   1,
						FirstMessageDeliveriesDecay:    0.999,
						FirstMessageDeliveriesCap:      100,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
				AppSpecificScore: func(peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -1,
				PublishThreshold:  -10,
				GraylistThreshold: -1000,
			}))

	bitmask, err := ps.Join([]byte{0xf1, 0x22, 0xb0, 0x22})
	if err != nil {
		t.Fatal(err)
	}

	err = bitmask.SetScoreParams(
		&BitmaskScoreParams{
			BitmaskWeight:                  1,
			TimeInMeshQuantum:              time.Second,
			FirstMessageDeliveriesWeight:   1,
			FirstMessageDeliveriesDecay:    0.999,
			FirstMessageDeliveriesCap:      200,
			InvalidMessageDeliveriesWeight: -1,
			InvalidMessageDeliveriesDecay:  0.9999,
		})
	if err != nil {
		t.Fatal(err)
	}
}

type mockPeerScoreInspector struct {
	mx     sync.Mutex
	scores map[peer.ID]float64
}

func (ps *mockPeerScoreInspector) inspect(scores map[peer.ID]float64) {
	ps.mx.Lock()
	defer ps.mx.Unlock()
	ps.scores = scores
}

func (ps *mockPeerScoreInspector) score(p peer.ID) float64 {
	ps.mx.Lock()
	defer ps.mx.Unlock()
	return ps.scores[p]
}

func TestBlossomSubRPCFragmentation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getNetHosts(t, ctx, 2)
	ps := getBlossomSub(ctx, hosts[0])

	// make a fake peer that requests everything through IWANT gossip
	iwe := iwantEverything{h: hosts[1]}
	iwe.h.SetStreamHandler(BlossomSubID_v12, iwe.handleStream)

	connect(t, hosts[0], hosts[1])

	// have the real pubsub join the test bitmask
	_, err := ps.Subscribe([]byte{0xf1, 0x22, 0xb0, 0x22})
	if err != nil {
		t.Fatal(err)
	}

	// wait for the real pubsub to connect and try to graft to the faker
	time.Sleep(time.Second)

	// publish a bunch of fairly large messages from the real host
	nMessages := 1000
	msgSize := 20000
	for i := 0; i < nMessages; i++ {
		msg := make([]byte, msgSize)
		rand.Read(msg)
		ps.Publish([]byte{0xf1, 0x22, 0xb0, 0x22}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// wait a bit for them to be received via gossip by the fake peer
	time.Sleep(5 * time.Second)
	iwe.lk.Lock()
	defer iwe.lk.Unlock()

	// we should have received all the messages
	if iwe.msgsReceived != nMessages {
		t.Fatalf("expected fake BlossomSub peer to receive all messages, got %d / %d", iwe.msgsReceived, nMessages)
	}

	// and we should have seen an IHAVE message for each of them
	if iwe.ihavesReceived != nMessages {
		t.Fatalf("expected to get IHAVEs for every message, got %d / %d", iwe.ihavesReceived, nMessages)
	}

	// If everything were fragmented with maximum efficiency, we would expect to get
	// (nMessages * msgSize) / ps.maxMessageSize total RPCs containing the messages we sent IWANTs for.
	// The actual number will probably be larger, since there's some overhead for the RPC itself, and
	// we probably aren't packing each RPC to it's maximum size
	minExpectedRPCS := (nMessages * msgSize) / ps.maxMessageSize
	if iwe.rpcsWithMessages < minExpectedRPCS {
		t.Fatalf("expected to receive at least %d RPCs containing messages, got %d", minExpectedRPCS, iwe.rpcsWithMessages)
	}
}

// iwantEverything is a simple BlossomSub client that never grafts onto a mesh,
// instead requesting everything through IWANT gossip messages. It is used to
// test that large responses to IWANT requests are fragmented into multiple RPCs.
type iwantEverything struct {
	h                host.Host
	lk               sync.Mutex
	rpcsWithMessages int
	msgsReceived     int
	ihavesReceived   int
}

func (iwe *iwantEverything) handleStream(s network.Stream) {
	defer s.Close()

	os, err := iwe.h.NewStream(context.Background(), s.Conn().RemotePeer(), BlossomSubID_v12)
	if err != nil {
		panic(err)
	}

	msgIdsReceived := make(map[string]struct{})
	gossipMsgIdsReceived := make(map[string]struct{})

	// send a subscription for test in the output stream to become candidate for gossip
	r := protoio.NewDelimitedReader(s, 1<<20)
	w := protoio.NewDelimitedWriter(os)
	truth := true
	bitmask := []byte{0xf1, 0x22, 0xb0, 0x22}
	err = w.WriteMsg(&pb.RPC{Subscriptions: []*pb.RPC_SubOpts{{Subscribe: truth, Bitmask: bitmask}}})
	if err != nil {
		panic(err)
	}

	var rpc pb.RPC
	for {
		rpc.Reset()
		err = r.ReadMsg(&rpc)
		if err != nil {
			if err != io.EOF {
				s.Reset()
			}
			return
		}

		iwe.lk.Lock()
		if len(rpc.Publish) != 0 {
			iwe.rpcsWithMessages++
		}
		// keep track of unique message ids received
		for _, msg := range rpc.Publish {
			id := string(msg.Seqno)
			if _, seen := msgIdsReceived[id]; !seen {
				iwe.msgsReceived++
			}
			msgIdsReceived[id] = struct{}{}
		}

		if rpc.Control != nil {
			// send a PRUNE for all grafts, so we don't get direct message deliveries
			var prunes []*pb.ControlPrune
			for _, graft := range rpc.Control.Graft {
				prunes = append(prunes, &pb.ControlPrune{Bitmask: graft.Bitmask})
			}

			var iwants []*pb.ControlIWant
			for _, ihave := range rpc.Control.Ihave {
				iwants = append(iwants, &pb.ControlIWant{MessageIDs: ihave.MessageIDs})
				for _, msgId := range ihave.MessageIDs {
					if _, seen := gossipMsgIdsReceived[msgId]; !seen {
						iwe.ihavesReceived++
					}
					gossipMsgIdsReceived[msgId] = struct{}{}
				}
			}

			out := rpcWithControl(nil, nil, iwants, nil, prunes)
			err = w.WriteMsg(out)
			if err != nil {
				panic(err)
			}
		}
		iwe.lk.Unlock()
	}
}

func TestFragmentRPCFunction(t *testing.T) {
	p := peer.ID("some-peer")
	bitmask := []byte{0xf1, 0x22, 0xb0, 0x22}
	rpc := &RPC{from: p}
	limit := 1024

	mkMsg := func(size int) *pb.Message {
		msg := &pb.Message{}
		msg.Data = make([]byte, size-4) // subtract the protobuf overhead, so msg.Size() returns requested size
		rand.Read(msg.Data)
		return msg
	}

	ensureBelowLimit := func(rpcs []*RPC) {
		for _, r := range rpcs {
			if r.Size() > limit {
				t.Fatalf("expected fragmented RPC to be below %d bytes, was %d", limit, r.Size())
			}
		}
	}

	// it should not fragment if everything fits in one RPC
	rpc.Publish = []*pb.Message{}
	rpc.Publish = []*pb.Message{mkMsg(10), mkMsg(10)}
	results, err := fragmentRPC(rpc, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected single RPC if input is < limit, got %d", len(results))
	}

	// if there's a message larger than the limit, we should fail
	rpc.Publish = []*pb.Message{mkMsg(10), mkMsg(limit * 2)}
	results, err = fragmentRPC(rpc, limit)
	if err == nil {
		t.Fatalf("expected an error if a message exceeds limit, got %d RPCs instead", len(results))
	}

	// if the individual messages are below the limit, but the RPC as a whole is larger, we should fragment
	nMessages := 100
	msgSize := 200
	truth := true
	rpc.Subscriptions = []*pb.RPC_SubOpts{
		{
			Subscribe: truth,
			Bitmask:   bitmask,
		},
	}
	rpc.Publish = make([]*pb.Message, nMessages)
	for i := 0; i < nMessages; i++ {
		rpc.Publish[i] = mkMsg(msgSize)
	}
	results, err = fragmentRPC(rpc, limit)
	if err != nil {
		t.Fatal(err)
	}
	ensureBelowLimit(results)
	msgsPerRPC := limit / msgSize
	expectedRPCs := nMessages / msgsPerRPC
	if len(results) != expectedRPCs {
		t.Fatalf("expected %d RPC messages in output, got %d", expectedRPCs, len(results))
	}
	var nMessagesFragmented int
	var nSubscriptions int
	for _, r := range results {
		nMessagesFragmented += len(r.Publish)
		nSubscriptions += len(r.Subscriptions)
	}
	if nMessagesFragmented != nMessages {
		t.Fatalf("expected fragemented RPCs to contain same number of messages as input, got %d / %d", nMessagesFragmented, nMessages)
	}
	if nSubscriptions != 1 {
		t.Fatal("expected subscription to be present in one of the fragmented messages, but not found")
	}

	// if we're fragmenting, and the input RPC has control messages,
	// the control messages should be in a separate RPC at the end
	// reuse RPC from prev test, but add a control message
	rpc.Control = &pb.ControlMessage{
		Graft: []*pb.ControlGraft{{Bitmask: bitmask}},
		Prune: []*pb.ControlPrune{{Bitmask: bitmask}},
		Ihave: []*pb.ControlIHave{{MessageIDs: []string{"foo"}}},
		Iwant: []*pb.ControlIWant{{MessageIDs: []string{"bar"}}},
	}
	results, err = fragmentRPC(rpc, limit)
	if err != nil {
		t.Fatal(err)
	}
	ensureBelowLimit(results)
	// we expect one more RPC than last time, with the final one containing the control messages
	expectedCtrl := 1
	expectedRPCs = (nMessages / msgsPerRPC) + expectedCtrl
	if len(results) != expectedRPCs {
		t.Fatalf("expected %d RPC messages in output, got %d", expectedRPCs, len(results))
	}
	ctl := results[len(results)-1].Control
	if ctl == nil {
		t.Fatal("expected final fragmented RPC to contain control messages, but .Control was nil")
	}
	// since it was not altered, the original control message should be identical to the output control message
	originalBytes, err := rpc.Control.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	receivedBytes, err := ctl.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, receivedBytes) {
		t.Fatal("expected control message to be unaltered if it fits within one RPC message")
	}

	// if the control message is too large to fit into a single RPC, it should be split into multiple RPCs
	nBitmasks := 5 // pretend we're subscribed to multiple bitmasks and sending IHAVE / IWANTs for each
	messageIdSize := 32
	msgsPerBitmask := 100 // enough that a single IHAVE or IWANT will exceed the limit
	rpc.Control.Ihave = make([]*pb.ControlIHave, nBitmasks)
	rpc.Control.Iwant = make([]*pb.ControlIWant, nBitmasks)
	for i := 0; i < nBitmasks; i++ {
		messageIds := make([]string, msgsPerBitmask)
		for m := 0; m < msgsPerBitmask; m++ {
			mid := make([]byte, messageIdSize)
			rand.Read(mid)
			messageIds[m] = string(mid)
		}
		rpc.Control.Ihave[i] = &pb.ControlIHave{MessageIDs: messageIds}
		rpc.Control.Iwant[i] = &pb.ControlIWant{MessageIDs: messageIds}
	}
	results, err = fragmentRPC(rpc, limit)
	if err != nil {
		t.Fatal(err)
	}
	ensureBelowLimit(results)
	minExpectedCtl := rpc.Control.Size() / limit
	minExpectedRPCs := (nMessages / msgsPerRPC) + minExpectedCtl
	if len(results) < minExpectedRPCs {
		t.Fatalf("expected at least %d total RPCs (at least %d with control messages), got %d total", expectedRPCs, expectedCtrl, len(results))
	}

	// Test the pathological case where a single gossip message ID exceeds the limit.
	// It should not be present in the fragmented messages, but smaller IDs should be
	rpc.Reset()
	giantIdBytes := make([]byte, limit*2)
	rand.Read(giantIdBytes)
	rpc.Control = &pb.ControlMessage{
		Iwant: []*pb.ControlIWant{
			{MessageIDs: []string{"hello", string(giantIdBytes)}},
		},
	}
	results, err = fragmentRPC(rpc, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 RPC, got %d", len(results))
	}
	if len(results[0].Control.Iwant) != 1 {
		t.Fatalf("expected 1 IWANT, got %d", len(results[0].Control.Iwant))
	}
	if results[0].Control.Iwant[0].MessageIDs[0] != "hello" {
		t.Fatalf("expected small message ID to be included unaltered, got %s instead",
			results[0].Control.Iwant[0].MessageIDs[0])
	}
}
