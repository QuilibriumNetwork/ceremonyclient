package blossomsub

import (
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

var (
	// BlossomSubConnTagBumpMessageDelivery is the amount to add to the connection manager
	// tag that tracks message deliveries. Each time a peer is the first to deliver a
	// message within a bitmask, we "bump" a tag by this amount, up to a maximum
	// of BlossomSubConnTagMessageDeliveryCap.
	// Note that the delivery tags decay over time, decreasing by BlossomSubConnTagDecayAmount
	// at every BlossomSubConnTagDecayInterval.
	BlossomSubConnTagBumpMessageDelivery = 1

	// BlossomSubConnTagDecayInterval is the decay interval for decaying connection manager tags.
	BlossomSubConnTagDecayInterval = 10 * time.Minute

	// BlossomSubConnTagDecayAmount is subtracted from decaying tag values at each decay interval.
	BlossomSubConnTagDecayAmount = 1

	// BlossomSubConnTagMessageDeliveryCap is the maximum value for the connection manager tags that
	// track message deliveries.
	BlossomSubConnTagMessageDeliveryCap = 15
)

// tagTracer is an internal tracer that applies connection manager tags to peer
// connections based on their behavior.
//
// We tag a peer's connections for the following reasons:
//   - Directly connected peers are tagged with BlossomSubConnTagValueDirectPeer (default 1000).
//   - Mesh peers are tagged with a value of BlossomSubConnTagValueMeshPeer (default 20).
//     If a peer is in multiple bitmask meshes, they'll be tagged for each.
//   - For each message that we receive, we bump a delivery tag for peer that delivered the message
//     first.
//     The delivery tags have a maximum value, BlossomSubConnTagMessageDeliveryCap, and they decay at
//     a rate of BlossomSubConnTagDecayAmount / BlossomSubConnTagDecayInterval.
type tagTracer struct {
	sync.RWMutex

	cmgr     connmgr.ConnManager
	idGen    *msgIDGenerator
	decayer  connmgr.Decayer
	decaying map[string]connmgr.DecayingTag
	direct   map[peer.ID]struct{}

	// a map of message ids to the set of peers who delivered the message after the first delivery,
	// but before the message was finished validating
	nearFirst map[string]map[peer.ID]struct{}
}

func newTagTracer(cmgr connmgr.ConnManager) *tagTracer {
	decayer, ok := connmgr.SupportsDecay(cmgr)
	if !ok {
		log.Debugf("connection manager does not support decaying tags, delivery tags will not be applied")
	}
	return &tagTracer{
		cmgr:      cmgr,
		idGen:     newMsgIdGenerator(),
		decayer:   decayer,
		decaying:  make(map[string]connmgr.DecayingTag),
		nearFirst: make(map[string]map[peer.ID]struct{}),
	}
}

func (t *tagTracer) Start(gs *BlossomSubRouter) {
	if t == nil {
		return
	}

	t.idGen = gs.p.idGen
	t.direct = gs.direct
}

func (t *tagTracer) tagPeerIfDirect(p peer.ID) {
	if t.direct == nil {
		return
	}

	// tag peer if it is a direct peer
	_, direct := t.direct[p]
	if direct {
		t.cmgr.Protect(p, "pubsub:<direct>")
	}
}

func (t *tagTracer) tagMeshPeer(p peer.ID, bitmask []byte) {
	tag := bitmaskTag(bitmask)
	t.cmgr.Protect(p, tag)
}

func (t *tagTracer) untagMeshPeer(p peer.ID, bitmask []byte) {
	tag := bitmaskTag(bitmask)
	t.cmgr.Unprotect(p, tag)
}

func bitmaskTag(bitmask []byte) string {
	return fmt.Sprintf("pubsub:%s", bitmask)
}

func (t *tagTracer) addDeliveryTag(bitmask []byte) {
	if t.decayer == nil {
		return
	}

	name := "pubsub-deliveries:" + string(bitmask)
	t.Lock()

	tag, err := t.decayer.RegisterDecayingTag(
		name,
		BlossomSubConnTagDecayInterval,
		connmgr.DecayFixed(BlossomSubConnTagDecayAmount),
		connmgr.BumpSumBounded(0, BlossomSubConnTagMessageDeliveryCap))

	if err != nil {
		log.Warnf("unable to create decaying delivery tag: %s", err)
		t.Unlock()
		return
	}
	t.decaying[string(bitmask)] = tag
	t.Unlock()
}

func (t *tagTracer) removeDeliveryTag(bitmask []byte) {
	t.Lock()

	tag, ok := t.decaying[string(bitmask)]
	if !ok {
		t.Unlock()
		return
	}
	err := tag.Close()
	if err != nil {
		log.Warnf("error closing decaying connmgr tag: %s", err)
	}
	delete(t.decaying, string(bitmask))
	t.Unlock()
}

func (t *tagTracer) bumpDeliveryTag(p peer.ID, bitmask []byte) error {
	t.RLock()

	tag, ok := t.decaying[string(bitmask)]
	if !ok {
		t.RUnlock()
		return fmt.Errorf("no decaying tag registered for bitmask %s", bitmask)
	}
	err := tag.Bump(p, BlossomSubConnTagBumpMessageDelivery)
	t.RUnlock()
	return err
}

func (t *tagTracer) bumpTagsForMessage(p peer.ID, msg *Message) {
	bitmask := msg.GetBitmask()
	err := t.bumpDeliveryTag(p, bitmask)
	if err != nil {
		log.Warnf("error bumping delivery tag: %s", err)
	}
}

// nearFirstPeers returns the peers who delivered the message while it was still validating
func (t *tagTracer) nearFirstPeers(msg *Message) []peer.ID {
	t.Lock()

	peersMap, ok := t.nearFirst[string(t.idGen.ID(msg))]
	if !ok {
		t.Unlock()
		return nil
	}
	peers := make([]peer.ID, 0, len(peersMap))
	for p := range peersMap {
		peers = append(peers, p)
	}
	t.Unlock()
	return peers
}

// -- RawTracer interface methods
var _ RawTracer = (*tagTracer)(nil)

func (t *tagTracer) AddPeer(p peer.ID, proto protocol.ID) {
	t.tagPeerIfDirect(p)
}

func (t *tagTracer) Join(bitmask []byte) {
	t.addDeliveryTag(bitmask)
}

func (t *tagTracer) DeliverMessage(msg *Message) {
	nearFirst := t.nearFirstPeers(msg)

	t.bumpTagsForMessage(msg.ReceivedFrom, msg)
	for _, p := range nearFirst {
		t.bumpTagsForMessage(p, msg)
	}

	// delete the delivery state for this message
	t.Lock()
	delete(t.nearFirst, string(t.idGen.ID(msg)))
	t.Unlock()
}

func (t *tagTracer) Leave(bitmask []byte) {
	t.removeDeliveryTag(bitmask)
}

func (t *tagTracer) Graft(p peer.ID, bitmask []byte) {
	t.tagMeshPeer(p, bitmask)
}

func (t *tagTracer) Prune(p peer.ID, bitmask []byte) {
	t.untagMeshPeer(p, bitmask)
}

func (t *tagTracer) ValidateMessage(msg *Message) {
	t.Lock()

	// create map to start tracking the peers who deliver while we're validating
	id := t.idGen.ID(msg)
	if _, exists := t.nearFirst[string(id)]; exists {
		t.Unlock()
		return
	}
	t.nearFirst[string(id)] = make(map[peer.ID]struct{})
	t.Unlock()
}

func (t *tagTracer) DuplicateMessage(msg *Message) {
	t.Lock()

	id := t.idGen.ID(msg)
	peers, ok := t.nearFirst[string(id)]
	if !ok {
		t.Unlock()
		return
	}
	peers[msg.ReceivedFrom] = struct{}{}
	t.Unlock()
}

func (t *tagTracer) RejectMessage(msg *Message, reason string) {
	t.Lock()

	// We want to delete the near-first delivery tracking for messages that have passed through
	// the validation pipeline. Other rejection reasons (missing signature, etc) skip the validation
	// queue, so we don't want to remove the state in case the message is still validating.
	switch reason {
	case RejectValidationThrottled:
		fallthrough
	case RejectValidationIgnored:
		fallthrough
	case RejectValidationFailed:
		delete(t.nearFirst, string(t.idGen.ID(msg)))
	}
	t.Unlock()
}

func (t *tagTracer) RemovePeer(peer.ID)                {}
func (t *tagTracer) ThrottlePeer(p peer.ID)            {}
func (t *tagTracer) RecvRPC(rpc *RPC)                  {}
func (t *tagTracer) SendRPC(rpc *RPC, p peer.ID)       {}
func (t *tagTracer) DropRPC(rpc *RPC, p peer.ID)       {}
func (t *tagTracer) UndeliverableMessage(msg *Message) {}
