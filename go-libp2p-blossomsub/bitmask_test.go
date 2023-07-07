package blossomsub

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	tnet "github.com/libp2p/go-libp2p-testing/net"
	"github.com/libp2p/go-libp2p/core/peer"
	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

func getBitmasks(psubs []*PubSub, bitmask []byte, opts ...BitmaskOpt) []*Bitmask {
	bitmasks := make([]*Bitmask, len(psubs))

	for i, ps := range psubs {
		t, err := ps.Join(bitmask, opts...)
		if err != nil {
			panic(err)
		}
		bitmasks[i] = t
	}

	return bitmasks
}

func getBitmaskEvts(bitmasks []*Bitmask, opts ...BitmaskEventHandlerOpt) []*BitmaskEventHandler {
	handlers := make([]*BitmaskEventHandler, len(bitmasks))

	for i, t := range bitmasks {
		h, err := t.EventHandler(opts...)
		if err != nil {
			panic(err)
		}
		handlers[i] = h
	}

	return handlers
}

func TestBitmaskCloseWithOpenSubscription(t *testing.T) {
	var sub *Subscription
	var err error
	testBitmaskCloseWithOpenResource(t,
		func(bitmask *Bitmask) {
			sub, err = bitmask.Subscribe()
			if err != nil {
				t.Fatal(err)
			}
		},
		func() {
			sub.Cancel()
		},
	)
}

func TestBitmaskCloseWithOpenEventHandler(t *testing.T) {
	var evts *BitmaskEventHandler
	var err error
	testBitmaskCloseWithOpenResource(t,
		func(bitmask *Bitmask) {
			evts, err = bitmask.EventHandler()
			if err != nil {
				t.Fatal(err)
			}
		},
		func() {
			evts.Cancel()
		},
	)
}

func TestBitmaskCloseWithOpenRelay(t *testing.T) {
	var relayCancel RelayCancelFunc
	var err error
	testBitmaskCloseWithOpenResource(t,
		func(bitmask *Bitmask) {
			relayCancel, err = bitmask.Relay()
			if err != nil {
				t.Fatal(err)
			}
		},
		func() {
			relayCancel()
		},
	)
}

func testBitmaskCloseWithOpenResource(t *testing.T, openResource func(bitmask *Bitmask), closeResource func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numHosts = 1
	bitmaskID := []byte{0xf0, 0x0b, 0xa1, 0x20}
	hosts := getNetHosts(t, ctx, numHosts)
	ps := getPubsub(ctx, hosts[0])

	// Try create and cancel bitmask
	bitmask, err := ps.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	if err := bitmask.Close(); err != nil {
		t.Fatal(err)
	}

	// Try create and cancel bitmask while there's an outstanding subscription/event handler
	bitmask, err = ps.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	openResource(bitmask)

	if err := bitmask.Close(); err == nil {
		t.Fatal("expected an error closing a bitmask with an open resource")
	}

	// Check if the bitmask closes properly after closing the resource
	closeResource()
	time.Sleep(time.Millisecond * 100)

	if err := bitmask.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBitmaskReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numHosts = 2
	bitmaskID := []byte{0xf0, 0x0b, 0xa1, 0x20}
	hosts := getNetHosts(t, ctx, numHosts)

	sender := getPubsub(ctx, hosts[0], WithDiscovery(&dummyDiscovery{}))
	receiver := getPubsub(ctx, hosts[1])

	connectAll(t, hosts)

	// Sender creates bitmask
	sendBitmask, err := sender.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver creates and subscribes to the bitmask
	receiveBitmask, err := receiver.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	sub, err := receiveBitmask.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	firstMsg := []byte("1")
	if err := sendBitmask.Publish(ctx, firstMsg, WithReadiness(MinBitmaskSize(1))); err != nil {
		t.Fatal(err)
	}

	msg, err := sub.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.GetData(), firstMsg) {
		t.Fatal("received incorrect message")
	}

	if err := sendBitmask.Close(); err != nil {
		t.Fatal(err)
	}

	// Recreate the same bitmask
	newSendBitmask, err := sender.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	// Try sending data with original bitmask
	illegalSend := []byte("illegal")
	if err := sendBitmask.Publish(ctx, illegalSend); err != ErrBitmaskClosed {
		t.Fatal(err)
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, time.Second*2)
	defer timeoutCancel()
	msg, err = sub.Next(timeoutCtx)
	if err != context.DeadlineExceeded {
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(msg.GetData(), illegalSend) {
			t.Fatal("received incorrect message from illegal bitmask")
		}
		t.Fatal("received message sent by illegal bitmask")
	}
	timeoutCancel()

	// Try cancelling the new bitmask by using the original bitmask
	if err := sendBitmask.Close(); err != nil {
		t.Fatal(err)
	}

	secondMsg := []byte("2")
	if err := newSendBitmask.Publish(ctx, secondMsg); err != nil {
		t.Fatal(err)
	}

	timeoutCtx, timeoutCancel = context.WithTimeout(ctx, time.Second*2)
	defer timeoutCancel()
	msg, err = sub.Next(timeoutCtx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.GetData(), secondMsg) {
		t.Fatal("received incorrect message")
	}
}

func TestBitmaskEventHandlerCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numHosts = 5
	bitmaskID := []byte{0xf0, 0x0b, 0xa1, 0x20}
	hosts := getNetHosts(t, ctx, numHosts)
	ps := getPubsub(ctx, hosts[0])

	// Try create and cancel bitmask
	bitmask, err := ps.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	evts, err := bitmask.EventHandler()
	if err != nil {
		t.Fatal(err)
	}
	evts.Cancel()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, time.Second*2)
	defer timeoutCancel()
	connectAll(t, hosts)
	_, err = evts.NextPeerEvent(timeoutCtx)
	if err != context.DeadlineExceeded {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("received event after cancel")
	}
}

func TestSubscriptionJoinNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numLateSubscribers = 10
	const numHosts = 20
	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), []byte{0xf0, 0x0b, 0xa1, 0x20})
	evts := getBitmaskEvts(bitmasks)

	subs := make([]*Subscription, numHosts)
	bitmaskPeersFound := make([]map[peer.ID]struct{}, numHosts)

	// Have some peers subscribe earlier than other peers.
	// This exercises whether we get subscription notifications from
	// existing peers.
	for i, bitmask := range bitmasks[numLateSubscribers:] {
		subch, err := bitmask.Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		subs[i] = subch
	}

	connectAll(t, hosts)

	time.Sleep(time.Millisecond * 100)

	// Have the rest subscribe
	for i, bitmask := range bitmasks[:numLateSubscribers] {
		subch, err := bitmask.Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		subs[i+numLateSubscribers] = subch
	}

	wg := sync.WaitGroup{}
	for i := 0; i < numHosts; i++ {
		peersFound := make(map[peer.ID]struct{})
		bitmaskPeersFound[i] = peersFound
		evt := evts[i]
		wg.Add(1)
		go func(peersFound map[peer.ID]struct{}) {
			defer wg.Done()
			for len(peersFound) < numHosts-1 {
				event, err := evt.NextPeerEvent(ctx)
				if err != nil {
					panic(err)
				}
				if event.Type == PeerJoin {
					peersFound[event.Peer] = struct{}{}
				}
			}
		}(peersFound)
	}

	wg.Wait()
	for _, peersFound := range bitmaskPeersFound {
		if len(peersFound) != numHosts-1 {
			t.Fatal("incorrect number of peers found")
		}
	}
}

func TestSubscriptionLeaveNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numHosts = 20
	hosts := getNetHosts(t, ctx, numHosts)
	psubs := getPubsubs(ctx, hosts)
	bitmasks := getBitmasks(psubs, []byte{0xf0, 0x0b, 0xa1, 0x20})
	evts := getBitmaskEvts(bitmasks)

	subs := make([]*Subscription, numHosts)
	bitmaskPeersFound := make([]map[peer.ID]struct{}, numHosts)

	// Subscribe all peers and wait until they've all been found
	for i, bitmask := range bitmasks {
		subch, err := bitmask.Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		subs[i] = subch
	}

	connectAll(t, hosts)

	time.Sleep(time.Millisecond * 100)

	wg := sync.WaitGroup{}
	for i := 0; i < numHosts; i++ {
		peersFound := make(map[peer.ID]struct{})
		bitmaskPeersFound[i] = peersFound
		evt := evts[i]
		wg.Add(1)
		go func(peersFound map[peer.ID]struct{}) {
			defer wg.Done()
			for len(peersFound) < numHosts-1 {
				event, err := evt.NextPeerEvent(ctx)
				if err != nil {
					panic(err)
				}
				if event.Type == PeerJoin {
					peersFound[event.Peer] = struct{}{}
				}
			}
		}(peersFound)
	}

	wg.Wait()
	for _, peersFound := range bitmaskPeersFound {
		if len(peersFound) != numHosts-1 {
			t.Fatal("incorrect number of peers found")
		}
	}

	// Test removing peers and verifying that they cause events
	subs[1].Cancel()
	_ = hosts[2].Close()
	psubs[0].BlacklistPeer(hosts[3].ID())

	leavingPeers := make(map[peer.ID]struct{})
	for len(leavingPeers) < 3 {
		event, err := evts[0].NextPeerEvent(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if event.Type == PeerLeave {
			leavingPeers[event.Peer] = struct{}{}
		}
	}

	if _, ok := leavingPeers[hosts[1].ID()]; !ok {
		t.Fatal(fmt.Errorf("canceling subscription did not cause a leave event"))
	}
	if _, ok := leavingPeers[hosts[2].ID()]; !ok {
		t.Fatal(fmt.Errorf("closing host did not cause a leave event"))
	}
	if _, ok := leavingPeers[hosts[3].ID()]; !ok {
		t.Fatal(fmt.Errorf("blacklisting peer did not cause a leave event"))
	}
}

func TestSubscriptionManyNotifications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}

	const numHosts = 33
	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)
	evts := getBitmaskEvts(bitmasks)

	subs := make([]*Subscription, numHosts)
	bitmaskPeersFound := make([]map[peer.ID]struct{}, numHosts)

	// Subscribe all peers except one and wait until they've all been found
	for i := 1; i < numHosts; i++ {
		subch, err := bitmasks[i].Subscribe()
		if err != nil {
			t.Fatal(err)
		}

		subs[i] = subch
	}

	connectAll(t, hosts)

	time.Sleep(time.Millisecond * 100)

	wg := sync.WaitGroup{}
	for i := 1; i < numHosts; i++ {
		peersFound := make(map[peer.ID]struct{})
		bitmaskPeersFound[i] = peersFound
		evt := evts[i]
		wg.Add(1)
		go func(peersFound map[peer.ID]struct{}) {
			defer wg.Done()
			for len(peersFound) < numHosts-2 {
				event, err := evt.NextPeerEvent(ctx)
				if err != nil {
					panic(err)
				}
				if event.Type == PeerJoin {
					peersFound[event.Peer] = struct{}{}
				}
			}
		}(peersFound)
	}

	wg.Wait()
	for _, peersFound := range bitmaskPeersFound[1:] {
		if len(peersFound) != numHosts-2 {
			t.Fatalf("found %d peers, expected %d", len(peersFound), numHosts-2)
		}
	}

	// Wait for remaining peer to find other peers
	remPeerBitmask, remPeerEvts := bitmasks[0], evts[0]
	for len(remPeerBitmask.ListPeers()) < numHosts-1 {
		time.Sleep(time.Millisecond * 100)
	}

	// Subscribe the remaining peer and check that all the events came through
	sub, err := remPeerBitmask.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	subs[0] = sub

	peerState := readAllQueuedEvents(ctx, t, remPeerEvts)

	if len(peerState) != numHosts-1 {
		t.Fatal("incorrect number of peers found")
	}

	for _, e := range peerState {
		if e != PeerJoin {
			t.Fatal("non Join event occurred")
		}
	}

	// Unsubscribe all peers except one and check that all the events came through
	for i := 1; i < numHosts; i++ {
		subs[i].Cancel()
	}

	// Wait for remaining peer to disconnect from the other peers
	for len(bitmasks[0].ListPeers()) != 0 {
		time.Sleep(time.Millisecond * 100)
	}

	peerState = readAllQueuedEvents(ctx, t, remPeerEvts)

	if len(peerState) != numHosts-1 {
		t.Fatal("incorrect number of peers found")
	}

	for _, e := range peerState {
		if e != PeerLeave {
			t.Fatal("non Leave event occurred")
		}
	}
}

func TestSubscriptionNotificationSubUnSub(t *testing.T) {
	// Resubscribe and Unsubscribe a peers and check the state for consistency
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}

	const numHosts = 35
	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)

	for i := 1; i < numHosts; i++ {
		connect(t, hosts[0], hosts[i])
	}
	time.Sleep(time.Millisecond * 100)

	notifSubThenUnSub(ctx, t, bitmasks)
}

func TestBitmaskRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}
	const numHosts = 5

	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)

	// [0.Rel] - [1.Rel] - [2.Sub]
	//             |
	//           [3.Rel] - [4.Sub]

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[1], hosts[3])
	connect(t, hosts[3], hosts[4])

	time.Sleep(time.Millisecond * 100)

	var subs []*Subscription

	for i, bitmask := range bitmasks {
		if i == 2 || i == 4 {
			sub, err := bitmask.Subscribe()
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, sub)
		} else {
			_, err := bitmask.Relay()
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	time.Sleep(time.Millisecond * 100)

	for i := 0; i < 100; i++ {
		msg := []byte("message")

		owner := rand.Intn(len(bitmasks))

		err := bitmasks[owner].Publish(ctx, msg)
		if err != nil {
			t.Fatal(err)
		}

		for _, sub := range subs {
			received, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(msg, received.Data) {
				t.Fatal("received message is other than expected")
			}
		}
	}
}

func TestBitmaskRelayReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}
	const numHosts = 1

	hosts := getNetHosts(t, ctx, numHosts)
	pubsubs := getPubsubs(ctx, hosts)
	bitmasks := getBitmasks(pubsubs, bitmask)

	relay1Cancel, err := bitmasks[0].Relay()
	if err != nil {
		t.Fatal(err)
	}

	relay2Cancel, err := bitmasks[0].Relay()
	if err != nil {
		t.Fatal(err)
	}

	relay3Cancel, err := bitmasks[0].Relay()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 100)

	res := make(chan bool, 1)
	pubsubs[0].eval <- func() {
		res <- pubsubs[0].myRelays[string(bitmask)] == 3
	}

	isCorrectNumber := <-res
	if !isCorrectNumber {
		t.Fatal("incorrect number of relays")
	}

	// only the first invocation should take effect
	relay1Cancel()
	relay1Cancel()
	relay1Cancel()

	pubsubs[0].eval <- func() {
		res <- pubsubs[0].myRelays[string(bitmask)] == 2
	}

	isCorrectNumber = <-res
	if !isCorrectNumber {
		t.Fatal("incorrect number of relays")
	}

	relay2Cancel()
	relay3Cancel()

	time.Sleep(time.Millisecond * 100)

	pubsubs[0].eval <- func() {
		res <- pubsubs[0].myRelays[string(bitmask)] == 0
	}

	isCorrectNumber = <-res
	if !isCorrectNumber {
		t.Fatal("incorrect number of relays")
	}
}

func TestBitmaskRelayOnClosedBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}
	const numHosts = 1

	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)

	err := bitmasks[0].Close()
	if err != nil {
		t.Fatal(err)
	}

	_, err = bitmasks[0].Relay()
	if err == nil {
		t.Fatalf("error should be returned")
	}
}

func TestProducePanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numHosts = 5
	bitmaskID := []byte{0xf0, 0x0b, 0xa1, 0x20}
	hosts := getNetHosts(t, ctx, numHosts)
	ps := getPubsub(ctx, hosts[0])

	// Create bitmask
	bitmask, err := ps.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	// Create subscription we're going to cancel
	s, err := bitmask.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	// Create second subscription to keep us alive on the subscription map
	// after the first one is canceled
	s2, err := bitmask.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	_ = s2

	s.Cancel()
	time.Sleep(time.Second)
	s.Cancel()
	time.Sleep(time.Second)
}

func notifSubThenUnSub(ctx context.Context, t *testing.T, bitmasks []*Bitmask) {
	primaryBitmask := bitmasks[0]
	msgs := make([]*Subscription, len(bitmasks))
	checkSize := len(bitmasks) - 1

	// Subscribe all peers to the bitmask
	var err error
	for i, bitmask := range bitmasks {
		msgs[i], err = bitmask.Subscribe()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Wait for the primary peer to be connected to the other peers
	for len(primaryBitmask.ListPeers()) < checkSize {
		time.Sleep(time.Millisecond * 100)
	}

	// Unsubscribe all peers except the primary
	for i := 1; i < checkSize+1; i++ {
		msgs[i].Cancel()
	}

	// Wait for the unsubscribe messages to reach the primary peer
	for len(primaryBitmask.ListPeers()) < 0 {
		time.Sleep(time.Millisecond * 100)
	}

	// read all available events and verify that there are no events to process
	// this is because every peer that joined also left
	primaryEvts, err := primaryBitmask.EventHandler()
	if err != nil {
		t.Fatal(err)
	}
	peerState := readAllQueuedEvents(ctx, t, primaryEvts)

	if len(peerState) != 0 {
		for p, s := range peerState {
			fmt.Println(p, s)
		}
		t.Fatalf("Received incorrect events. %d extra events", len(peerState))
	}
}

func readAllQueuedEvents(ctx context.Context, t *testing.T, evt *BitmaskEventHandler) map[peer.ID]EventType {
	peerState := make(map[peer.ID]EventType)
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Millisecond*100)
		event, err := evt.NextPeerEvent(ctx)
		cancel()

		if err == context.DeadlineExceeded {
			break
		} else if err != nil {
			t.Fatal(err)
		}

		e, ok := peerState[event.Peer]
		if !ok {
			peerState[event.Peer] = event.Type
		} else if e != event.Type {
			delete(peerState, event.Peer)
		}
	}
	return peerState
}

func TestMinBitmaskSizeNoDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const numHosts = 3
	bitmaskID := []byte{0xf0, 0x0b, 0xa1, 0x20}
	hosts := getNetHosts(t, ctx, numHosts)

	sender := getPubsub(ctx, hosts[0])
	receiver1 := getPubsub(ctx, hosts[1])
	receiver2 := getPubsub(ctx, hosts[2])

	connectAll(t, hosts)

	// Sender creates bitmask
	sendBitmask, err := sender.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver creates and subscribes to the bitmask
	receiveBitmask1, err := receiver1.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	sub1, err := receiveBitmask1.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	oneMsg := []byte("minimum one")
	if err := sendBitmask.Publish(ctx, oneMsg, WithReadiness(MinBitmaskSize(1))); err != nil {
		t.Fatal(err)
	}

	if msg, err := sub1.Next(ctx); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(msg.GetData(), oneMsg) {
		t.Fatal("received incorrect message")
	}

	twoMsg := []byte("minimum two")

	// Attempting to publish with a minimum bitmask size of two should fail.
	{
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := sendBitmask.Publish(ctx, twoMsg, WithReadiness(MinBitmaskSize(2))); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}

	// Subscribe the second receiver; the publish should now work.
	receiveBitmask2, err := receiver2.Join(bitmaskID)
	if err != nil {
		t.Fatal(err)
	}

	sub2, err := receiveBitmask2.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	{
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := sendBitmask.Publish(ctx, twoMsg, WithReadiness(MinBitmaskSize(2))); err != nil {
			t.Fatal(err)
		}
	}

	if msg, err := sub2.Next(ctx); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(msg.GetData(), twoMsg) {
		t.Fatal("received incorrect message")
	}
}

func TestWithBitmaskMsgIdFunction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmaskA, bitmaskB := []byte{0xf0, 0x0b, 0xa1, 0x2a}, []byte{0xf0, 0x0b, 0xa1, 0x2b}
	const numHosts = 2

	hosts := getNetHosts(t, ctx, numHosts)
	pubsubs := getPubsubs(ctx, hosts, WithMessageIdFn(func(pmsg *pb.Message) string {
		hash := sha256.Sum256(pmsg.Data)
		return string(hash[:])
	}))
	connectAll(t, hosts)

	bitmasksA := getBitmasks(pubsubs, bitmaskA)                                                        // uses global msgIdFn
	bitmasksB := getBitmasks(pubsubs, bitmaskB, WithBitmaskMessageIdFn(func(pmsg *pb.Message) string { // uses custom
		hash := sha1.Sum(pmsg.Data)
		return string(hash[:])
	}))

	payload := []byte("pubsub rocks")

	subA, err := bitmasksA[0].Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	err = bitmasksA[1].Publish(ctx, payload, WithReadiness(MinBitmaskSize(1)))
	if err != nil {
		t.Fatal(err)
	}

	msgA, err := subA.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	subB, err := bitmasksB[0].Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	err = bitmasksB[1].Publish(ctx, payload, WithReadiness(MinBitmaskSize(1)))
	if err != nil {
		t.Fatal(err)
	}

	msgB, err := subB.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if msgA.ID == msgB.ID {
		t.Fatal("msg ids are equal")
	}
}

func TestBitmaskPublishWithKeyInvalidParameters(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}
	const numHosts = 5

	virtualPeer := tnet.RandPeerNetParamsOrFatal(t)
	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)

	t.Run("nil sign private key should error", func(t *testing.T) {
		withVirtualKey := WithSecretKeyAndPeerId(nil, virtualPeer.ID)
		err := bitmasks[0].Publish(ctx, []byte("buff"), withVirtualKey)
		if err != ErrNilSignKey {
			t.Fatal("error should have been of type errNilSignKey")
		}
	})
	t.Run("empty peer ID should error", func(t *testing.T) {
		withVirtualKey := WithSecretKeyAndPeerId(virtualPeer.PrivKey, "")
		err := bitmasks[0].Publish(ctx, []byte("buff"), withVirtualKey)
		if err != ErrEmptyPeerID {
			t.Fatal("error should have been of type errEmptyPeerID")
		}
	})
}

func TestBitmaskRelayPublishWithKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bitmask := []byte{0xf0, 0x0b, 0xa1, 0x20}
	const numHosts = 5

	virtualPeer := tnet.RandPeerNetParamsOrFatal(t)
	hosts := getNetHosts(t, ctx, numHosts)
	bitmasks := getBitmasks(getPubsubs(ctx, hosts), bitmask)

	// [0.Rel] - [1.Rel] - [2.Sub]
	//             |
	//           [3.Rel] - [4.Sub]

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[1], hosts[3])
	connect(t, hosts[3], hosts[4])

	time.Sleep(time.Millisecond * 100)

	var subs []*Subscription

	for i, bitmaskValue := range bitmasks {
		if i == 2 || i == 4 {
			sub, err := bitmaskValue.Subscribe()
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, sub)
		} else {
			_, err := bitmaskValue.Relay()
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	time.Sleep(time.Millisecond * 100)

	for i := 0; i < 100; i++ {
		msg := []byte("message")

		owner := rand.Intn(len(bitmasks))

		withVirtualKey := WithSecretKeyAndPeerId(virtualPeer.PrivKey, virtualPeer.ID)
		err := bitmasks[owner].Publish(ctx, msg, withVirtualKey)
		if err != nil {
			t.Fatal(err)
		}

		for _, sub := range subs {
			received, errSub := sub.Next(ctx)
			if errSub != nil {
				t.Fatal(errSub)
			}

			if !bytes.Equal(msg, received.Data) {
				t.Fatal("received message is other than expected")
			}
			if string(received.From) != string(virtualPeer.ID) {
				t.Fatal("received message is not from the virtual peer")
			}
		}
	}
}

func TestWithLocalPublication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bitmask := []byte{0x7e, 57}

	hosts := getNetHosts(t, ctx, 2)
	pubsubs := getPubsubs(ctx, hosts)
	bitmasks := getBitmasks(pubsubs, bitmask)
	connectAll(t, hosts)

	payload := []byte("pubsub smashes")

	local, err := bitmasks[0].Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	remote, err := bitmasks[1].Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	err = bitmasks[0].Publish(ctx, payload, WithLocalPublication(true))
	if err != nil {
		t.Fatal(err)
	}

	remoteCtx, cancel := context.WithTimeout(ctx, time.Millisecond*100)
	defer cancel()

	msg, err := remote.Next(remoteCtx)
	if msg != nil || err == nil {
		t.Fatal("unexpected msg")
	}

	msg, err = local.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Local || !bytes.Equal(msg.Data, payload) {
		t.Fatal("wrong message")
	}
}
