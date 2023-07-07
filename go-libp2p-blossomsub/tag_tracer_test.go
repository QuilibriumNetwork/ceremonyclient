package blossomsub

import (
	"fmt"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	connmgri "github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

func TestTagTracerMeshTags(t *testing.T) {
	// test that tags are applied when the tagTracer sees graft and prune events

	cmgr, err := connmgr.NewConnManager(5, 10, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	tt := newTagTracer(cmgr)

	p := peer.ID("a-peer")
	bitmask := []byte{0xff, 0x00, 0xff, 0x00}

	tt.Join(bitmask)
	tt.Graft(p, bitmask)

	tag := "pubsub:" + string(bitmask)
	if !cmgr.IsProtected(p, tag) {
		t.Fatal("expected the mesh peer to be protected")
	}

	tt.Prune(p, bitmask)
	if cmgr.IsProtected(p, tag) {
		t.Fatal("expected the former mesh peer to be unprotected")
	}
}

func TestTagTracerDirectPeerTags(t *testing.T) {
	// test that we add a tag to direct peers
	cmgr, err := connmgr.NewConnManager(5, 10, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	tt := newTagTracer(cmgr)

	p1 := peer.ID("1")
	p2 := peer.ID("2")
	p3 := peer.ID("3")

	// in the real world, tagTracer.direct is set in the WithDirectPeers option function
	tt.direct = make(map[peer.ID]struct{})
	tt.direct[p1] = struct{}{}

	tt.AddPeer(p1, BlossomSubID_v11)
	tt.AddPeer(p2, BlossomSubID_v11)
	tt.AddPeer(p3, BlossomSubID_v11)

	tag := "pubsub:<direct>"
	if !cmgr.IsProtected(p1, tag) {
		t.Fatal("expected direct peer to be protected")
	}

	for _, p := range []peer.ID{p2, p3} {
		if cmgr.IsProtected(p, tag) {
			t.Fatal("expected non-direct peer to be unprotected")
		}
	}
}

func TestTagTracerDeliveryTags(t *testing.T) {
	t.Skip("flaky test temporarily disabled; TODO: fixme")
	// test decaying delivery tags

	// use fake time to test the tag decay
	clk := clock.NewMock()
	decayCfg := &connmgr.DecayerCfg{
		Clock:      clk,
		Resolution: time.Minute,
	}
	cmgr, err := connmgr.NewConnManager(5, 10, connmgr.WithGracePeriod(time.Minute), connmgr.DecayerConfig(decayCfg))
	if err != nil {
		t.Fatal(err)
	}

	tt := newTagTracer(cmgr)

	bitmask1 := []byte{0xff, 0x00, 0xff, 0x00}
	bitmask2 := []byte{0x00, 0xff, 0x00, 0xff}

	p := peer.ID("a-peer")

	tt.Join(bitmask1)
	tt.Join(bitmask2)

	for i := 0; i < 20; i++ {
		// deliver only 5 messages to bitmask 2 (less than the cap)
		bitmask := bitmask1
		if i < 5 {
			bitmask = bitmask2
		}
		msg := &Message{
			ReceivedFrom: p,
			Message: &pb.Message{
				From:    []byte(p),
				Data:    []byte("hello"),
				Bitmask: bitmask,
			},
		}
		tt.DeliverMessage(msg)
	}

	// we have to tick the fake clock once to apply the bump
	clk.Add(time.Minute)

	tag1 := "pubsub-deliveries:" + string(bitmask1)
	tag2 := "pubsub-deliveries:" + string(bitmask2)

	// the tag value for bitmask-1 should be capped at BlossomSubConnTagMessageDeliveryCap (default 15)
	val := getTagValue(cmgr, p, tag1)
	expected := BlossomSubConnTagMessageDeliveryCap
	if val != expected {
		t.Errorf("expected delivery tag to be capped at %d, was %d", expected, val)
	}

	// the value for bitmask-2 should equal the number of messages delivered (5), since it was less than the cap
	val = getTagValue(cmgr, p, tag2)
	expected = 5
	if val != expected {
		t.Errorf("expected delivery tag value = %d, got %d", expected, val)
	}

	// if we jump forward a few minutes, we should see the tags decrease by 1 / 10 minutes
	clk.Add(50 * time.Minute)
	time.Sleep(2 * time.Second)

	val = getTagValue(cmgr, p, tag1)
	expected = BlossomSubConnTagMessageDeliveryCap - 5
	// the actual expected value should be BlossomSubConnTagMessageDeliveryCap - 5,
	// however due to timing issues on Travis, we consistently get BlossomSubConnTagMessageDeliveryCap - 4
	// there instead. So our assertion checks for the expected value +/- 1
	if val > expected+1 || val < expected-1 {
		t.Errorf("expected delivery tag value = %d ± 1, got %d", expected, val)
	}

	// the tag for bitmask-2 should have reset to zero by now, but again we add one for Travis since it's slow...
	val = getTagValue(cmgr, p, tag2)
	expected = 0
	if val > expected+1 || val < expected-1 {
		t.Errorf("expected delivery tag value = %d ± 1, got %d", expected, val)
	}

	// leaving the bitmask should remove the tag
	if !tagExists(cmgr, p, tag1) {
		t.Errorf("expected delivery tag %s to be applied to peer %s", tag1, p)
	}
	tt.Leave(bitmask1)
	// advance the real clock a bit to allow the connmgr to remove the tag async
	time.Sleep(time.Second)
	if tagExists(cmgr, p, tag1) {
		t.Errorf("expected delivery tag %s to be removed after leaving the bitmask", tag1)
	}
}

func TestTagTracerDeliveryTagsNearFirst(t *testing.T) {
	// use fake time to test the tag decay
	clk := clock.NewMock()
	decayCfg := &connmgr.DecayerCfg{
		Clock:      clk,
		Resolution: time.Minute,
	}
	cmgr, err := connmgr.NewConnManager(5, 10, connmgr.WithGracePeriod(time.Minute), connmgr.DecayerConfig(decayCfg))
	if err != nil {
		t.Fatal(err)
	}

	tt := newTagTracer(cmgr)

	bitmask := []byte{0x7e, 0x57}

	p := peer.ID("a-peer")
	p2 := peer.ID("another-peer")
	p3 := peer.ID("slow-peer")

	tt.Join(bitmask)

	for i := 0; i < BlossomSubConnTagMessageDeliveryCap+5; i++ {
		msg := &Message{
			ReceivedFrom: p,
			Message: &pb.Message{
				From:    []byte(p),
				Data:    []byte(fmt.Sprintf("msg-%d", i)),
				Bitmask: bitmask,
				Seqno:   []byte(fmt.Sprintf("%d", i)),
			},
		}

		// a duplicate of the message, received from p2
		dup := &Message{
			ReceivedFrom: p2,
			Message:      msg.Message,
		}

		// the message starts validating as soon as we receive it from p
		tt.ValidateMessage(msg)
		// p2 should get near-first credit for the duplicate message that arrives before
		// validation is complete
		tt.DuplicateMessage(dup)
		// DeliverMessage gets called when validation is complete
		tt.DeliverMessage(msg)

		// p3 delivers a duplicate after validation completes & gets no credit
		dup.ReceivedFrom = p3
		tt.DuplicateMessage(dup)
	}

	clk.Add(time.Minute)

	// both p and p2 should get delivery tags equal to the cap
	tag := "pubsub-deliveries:" + string(bitmask)
	val := getTagValue(cmgr, p, tag)
	if val != BlossomSubConnTagMessageDeliveryCap {
		t.Errorf("expected tag %s to have val %d, was %d", tag, BlossomSubConnTagMessageDeliveryCap, val)
	}
	val = getTagValue(cmgr, p2, tag)
	if val != BlossomSubConnTagMessageDeliveryCap {
		t.Errorf("expected tag %s for near-first peer to have val %d, was %d", tag, BlossomSubConnTagMessageDeliveryCap, val)
	}

	// p3 should have no delivery tag credit
	val = getTagValue(cmgr, p3, tag)
	if val != 0 {
		t.Errorf("expected tag %s for slow peer to have val %d, was %d", tag, 0, val)
	}
}

func getTagValue(mgr connmgri.ConnManager, p peer.ID, tag string) int {
	info := mgr.GetTagInfo(p)
	if info == nil {
		return 0
	}
	val, ok := info.Tags[tag]
	if !ok {
		return 0
	}
	return val
}

//lint:ignore U1000 used only by skipped tests at present
func tagExists(mgr connmgri.ConnManager, p peer.ID, tag string) bool {
	info := mgr.GetTagInfo(p)
	if info == nil {
		return false
	}
	_, exists := info.Tags[tag]
	return exists
}
