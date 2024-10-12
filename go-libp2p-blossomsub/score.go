package blossomsub

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	manet "github.com/multiformats/go-multiaddr/net"
)

type peerStats struct {
	// true if the peer is currently connected
	connected bool

	// expiration time of the score stats for disconnected peers
	expire time.Time

	// per topc stats
	bitmasks map[string]*bitmaskStats

	// IP tracking; store as string for easy processing
	ips []string

	// IP whitelisting cache
	ipWhitelist map[string]bool

	// behavioural pattern penalties (applied by the router)
	behaviourPenalty float64
}

type bitmaskStats struct {
	// true if the peer is in the mesh
	inMesh bool

	// time when the peer was (last) GRAFTed; valid only when in mesh
	graftTime time.Time

	// time in mesh (updated during refresh/decay to avoid calling gettimeofday on
	// every score invocation)
	meshTime time.Duration

	// first message deliveries
	firstMessageDeliveries float64

	// mesh message deliveries
	meshMessageDeliveries float64

	// true if the peer has been enough time in the mesh to activate mess message deliveries
	meshMessageDeliveriesActive bool

	// sticky mesh rate failure penalty counter
	meshFailurePenalty float64

	// invalid message counter
	invalidMessageDeliveries float64
}

type peerScore struct {
	sync.Mutex

	// the score parameters
	params *PeerScoreParams

	// per peer stats for score calculation
	peerStats map[peer.ID]*peerStats

	// IP colocation tracking; maps IP => set of peers.
	peerIPs map[string]map[peer.ID]struct{}

	// message delivery tracking
	deliveries *messageDeliveries

	idGen *msgIDGenerator
	host  host.Host

	// debugging inspection
	inspect       PeerScoreInspectFn
	inspectEx     ExtendedPeerScoreInspectFn
	inspectPeriod time.Duration
}

var _ RawTracer = (*peerScore)(nil)

type messageDeliveries struct {
	seenMsgTTL time.Duration

	records map[string]*deliveryRecord

	// queue for cleaning up old delivery records
	head *deliveryEntry
	tail *deliveryEntry
}

type deliveryRecord struct {
	status    int
	firstSeen time.Time
	validated time.Time
	peers     map[peer.ID]struct{}
}

type deliveryEntry struct {
	id     []byte
	expire time.Time
	next   *deliveryEntry
}

// delivery record status
const (
	deliveryUnknown   = iota // we don't know (yet) if the message is valid
	deliveryValid            // we know the message is valid
	deliveryInvalid          // we know the message is invalid
	deliveryIgnored          // we were intructed by the validator to ignore the message
	deliveryThrottled        // we can't tell if it is valid because validation throttled
)

type (
	PeerScoreInspectFn         = func(map[peer.ID]float64)
	ExtendedPeerScoreInspectFn = func(map[peer.ID]*PeerScoreSnapshot)
)

type PeerScoreSnapshot struct {
	Score              float64
	Bitmasks           map[string]*BitmaskScoreSnapshot
	AppSpecificScore   float64
	IPColocationFactor float64
	BehaviourPenalty   float64
}

type BitmaskScoreSnapshot struct {
	TimeInMesh               time.Duration
	FirstMessageDeliveries   float64
	MeshMessageDeliveries    float64
	InvalidMessageDeliveries float64
}

// WithPeerScoreInspect is a BlossomSub router option that enables peer score debugging.
// When this option is enabled, the supplied function will be invoked periodically to allow
// the application to inspect or dump the scores for connected peers.
// The supplied function can have one of two signatures:
//   - PeerScoreInspectFn, which takes a map of peer IDs to score.
//   - ExtendedPeerScoreInspectFn, which takes a map of peer IDs to
//     PeerScoreSnapshots and allows inspection of individual score
//     components for debugging peer scoring.
//
// This option must be passed _after_ the WithPeerScore option.
func WithPeerScoreInspect(inspect interface{}, period time.Duration) Option {
	return func(ps *PubSub) error {
		gs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		if gs.score == nil {
			return fmt.Errorf("peer scoring is not enabled")
		}

		if gs.score.inspect != nil || gs.score.inspectEx != nil {
			return fmt.Errorf("duplicate peer score inspector")
		}

		switch i := inspect.(type) {
		case PeerScoreInspectFn:
			gs.score.inspect = i
		case ExtendedPeerScoreInspectFn:
			gs.score.inspectEx = i
		default:
			return fmt.Errorf("unknown peer score insector type: %v", inspect)
		}

		gs.score.inspectPeriod = period

		return nil
	}
}

// implementation
func newPeerScore(params *PeerScoreParams) *peerScore {
	seenMsgTTL := params.SeenMsgTTL
	if seenMsgTTL == 0 {
		seenMsgTTL = TimeCacheDuration
	}
	return &peerScore{
		params:     params,
		peerStats:  make(map[peer.ID]*peerStats),
		peerIPs:    make(map[string]map[peer.ID]struct{}),
		deliveries: &messageDeliveries{seenMsgTTL: seenMsgTTL, records: make(map[string]*deliveryRecord)},
		idGen:      newMsgIdGenerator(),
	}
}

// SetBitmaskScoreParams sets new score parameters for a bitmask.
// If the bitmask previously had parameters and the parameters are lowering delivery caps,
// then the score counters are recapped appropriately.
// Note: assumes that the bitmask score parameters have already been validated
func (ps *peerScore) SetBitmaskScoreParams(bitmask []byte, p *BitmaskScoreParams) error {
	ps.Lock()

	old, exist := ps.params.Bitmasks[string(bitmask)]
	ps.params.Bitmasks[string(bitmask)] = p

	if !exist {
		ps.Unlock()
		return nil
	}

	// check to see if the counter Caps are being lowered; if that's the case we need to recap them
	recap := false
	if p.FirstMessageDeliveriesCap < old.FirstMessageDeliveriesCap {
		recap = true
	}
	if p.MeshMessageDeliveriesCap < old.MeshMessageDeliveriesCap {
		recap = true
	}
	if !recap {
		ps.Unlock()
		return nil
	}

	// recap counters for bitmask
	for _, pstats := range ps.peerStats {
		tstats, ok := pstats.bitmasks[string(bitmask)]
		if !ok {
			continue
		}

		if tstats.firstMessageDeliveries > p.FirstMessageDeliveriesCap {
			tstats.firstMessageDeliveries = p.FirstMessageDeliveriesCap
		}

		if tstats.meshMessageDeliveries > p.MeshMessageDeliveriesCap {
			tstats.meshMessageDeliveries = p.MeshMessageDeliveriesCap
		}
	}
	ps.Unlock()
	return nil
}

// router interface
func (ps *peerScore) Start(gs *BlossomSubRouter) {
	if ps == nil {
		return
	}

	ps.idGen = gs.p.idGen
	ps.host = gs.p.host
	go ps.background(gs.p.ctx)
}

func (ps *peerScore) Score(p peer.ID) float64 {
	if ps == nil {
		return 0
	}

	ps.Lock()

	score := ps.score(p)
	ps.Unlock()
	return score
}

func (ps *peerScore) score(p peer.ID) float64 {
	pstats, ok := ps.peerStats[p]
	if !ok {
		return 0
	}

	var score float64

	// bitmask scores
	for bitmask, tstats := range pstats.bitmasks {
		// the bitmask parameters
		bitmaskParams, ok := ps.params.Bitmasks[string(bitmask)]
		if !ok {
			// we are not scoring this bitmask
			continue
		}

		// the bitmask score
		var bitmaskScore float64

		// P1: time in Mesh
		if tstats.inMesh {
			p1 := float64(tstats.meshTime / bitmaskParams.TimeInMeshQuantum)
			if p1 > bitmaskParams.TimeInMeshCap {
				p1 = bitmaskParams.TimeInMeshCap
			}
			bitmaskScore += p1 * bitmaskParams.TimeInMeshWeight
		}

		// P2: first message deliveries
		p2 := tstats.firstMessageDeliveries
		bitmaskScore += p2 * bitmaskParams.FirstMessageDeliveriesWeight

		// P3: mesh message deliveries
		if tstats.meshMessageDeliveriesActive {
			if tstats.meshMessageDeliveries < bitmaskParams.MeshMessageDeliveriesThreshold {
				deficit := bitmaskParams.MeshMessageDeliveriesThreshold - tstats.meshMessageDeliveries
				p3 := deficit * deficit
				bitmaskScore += p3 * bitmaskParams.MeshMessageDeliveriesWeight
			}
		}

		// P3b:
		// NOTE: the weight of P3b is negative (validated in BitmaskScoreParams.validate), so this detracts.
		p3b := tstats.meshFailurePenalty
		bitmaskScore += p3b * bitmaskParams.MeshFailurePenaltyWeight

		// P4: invalid messages
		// NOTE: the weight of P4 is negative (validated in BitmaskScoreParams.validate), so this detracts.
		p4 := (tstats.invalidMessageDeliveries * tstats.invalidMessageDeliveries)
		bitmaskScore += p4 * bitmaskParams.InvalidMessageDeliveriesWeight

		// update score, mixing with bitmask weight
		score += bitmaskScore * bitmaskParams.BitmaskWeight
	}

	// apply the bitmask score cap, if any
	if ps.params.BitmaskScoreCap > 0 && score > ps.params.BitmaskScoreCap {
		score = ps.params.BitmaskScoreCap
	}

	// P5: application-specific score
	p5 := ps.params.AppSpecificScore(p)
	score += p5 * ps.params.AppSpecificWeight

	// P6: IP collocation factor
	p6 := ps.ipColocationFactor(p)
	score += p6 * ps.params.IPColocationFactorWeight

	// P7: behavioural pattern penalty
	if pstats.behaviourPenalty > ps.params.BehaviourPenaltyThreshold {
		excess := pstats.behaviourPenalty - ps.params.BehaviourPenaltyThreshold
		p7 := excess * excess
		score += p7 * ps.params.BehaviourPenaltyWeight
	}

	return score
}

func (ps *peerScore) ipColocationFactor(p peer.ID) float64 {
	pstats, ok := ps.peerStats[p]
	if !ok {
		return 0
	}

	var result float64
loop:
	for _, ip := range pstats.ips {
		if len(ps.params.IPColocationFactorWhitelist) > 0 {
			if pstats.ipWhitelist == nil {
				pstats.ipWhitelist = make(map[string]bool)
			}

			whitelisted, ok := pstats.ipWhitelist[ip]
			if !ok {
				ipObj := net.ParseIP(ip)
				for _, ipNet := range ps.params.IPColocationFactorWhitelist {
					if ipNet.Contains(ipObj) {
						pstats.ipWhitelist[ip] = true
						continue loop
					}
				}

				pstats.ipWhitelist[ip] = false
			}

			if whitelisted {
				continue loop
			}
		}

		// P6 has a cliff (IPColocationFactorThreshold); it's only applied iff
		// at least that many peers are connected to us from that source IP
		// addr. It is quadratic, and the weight is negative (validated by
		// PeerScoreParams.validate).
		peersInIP := len(ps.peerIPs[ip])
		if peersInIP > ps.params.IPColocationFactorThreshold {
			surpluss := float64(peersInIP - ps.params.IPColocationFactorThreshold)
			result += surpluss * surpluss
		}
	}

	return result
}

// behavioural pattern penalties
func (ps *peerScore) AddPenalty(p peer.ID, count int) {
	if ps == nil {
		return
	}

	ps.Lock()

	pstats, ok := ps.peerStats[p]
	if !ok {
		ps.Unlock()
		return
	}

	pstats.behaviourPenalty += float64(count)
	ps.Unlock()
}

// periodic maintenance
func (ps *peerScore) background(ctx context.Context) {
	refreshScores := time.NewTicker(ps.params.DecayInterval)
	defer refreshScores.Stop()

	refreshIPs := time.NewTicker(time.Minute)
	defer refreshIPs.Stop()

	gcDeliveryRecords := time.NewTicker(time.Minute)
	defer gcDeliveryRecords.Stop()

	var inspectScores <-chan time.Time
	if ps.inspect != nil || ps.inspectEx != nil {
		ticker := time.NewTicker(ps.inspectPeriod)
		defer ticker.Stop()
		// also dump at exit for one final sample
		defer ps.inspectScores()
		inspectScores = ticker.C
	}

	for {
		select {
		case <-refreshScores.C:
			ps.refreshScores()

		case <-refreshIPs.C:
			ps.refreshIPs()

		case <-gcDeliveryRecords.C:
			ps.gcDeliveryRecords()

		case <-inspectScores:
			ps.inspectScores()

		case <-ctx.Done():
			return
		}
	}
}

// inspectScores dumps all tracked scores into the inspect function.
func (ps *peerScore) inspectScores() {
	if ps.inspect != nil {
		ps.inspectScoresSimple()
	}
	if ps.inspectEx != nil {
		ps.inspectScoresExtended()
	}
}

func (ps *peerScore) inspectScoresSimple() {
	ps.Lock()
	scores := make(map[peer.ID]float64, len(ps.peerStats))
	for p := range ps.peerStats {
		scores[p] = ps.score(p)
	}
	ps.Unlock()

	// Since this is a user-injected function, it could be performing I/O, and
	// we don't want to block the scorer's background loop. Therefore, we launch
	// it in a separate goroutine. If the function needs to synchronise, it
	// should do so locally.
	go ps.inspect(scores)
}

func (ps *peerScore) inspectScoresExtended() {
	ps.Lock()
	scores := make(map[peer.ID]*PeerScoreSnapshot, len(ps.peerStats))
	for p, pstats := range ps.peerStats {
		pss := new(PeerScoreSnapshot)
		pss.Score = ps.score(p)
		if len(pstats.bitmasks) > 0 {
			pss.Bitmasks = make(map[string]*BitmaskScoreSnapshot, len(pstats.bitmasks))
			for t, ts := range pstats.bitmasks {
				tss := &BitmaskScoreSnapshot{
					FirstMessageDeliveries:   ts.firstMessageDeliveries,
					MeshMessageDeliveries:    ts.meshMessageDeliveries,
					InvalidMessageDeliveries: ts.invalidMessageDeliveries,
				}
				if ts.inMesh {
					tss.TimeInMesh = ts.meshTime
				}
				pss.Bitmasks[t] = tss
			}
		}
		pss.AppSpecificScore = ps.params.AppSpecificScore(p)
		pss.IPColocationFactor = ps.ipColocationFactor(p)
		pss.BehaviourPenalty = pstats.behaviourPenalty
		scores[p] = pss
	}
	ps.Unlock()

	go ps.inspectEx(scores)
}

// refreshScores decays scores, and purges score records for disconnected peers,
// once their expiry has elapsed.
func (ps *peerScore) refreshScores() {
	ps.Lock()

	now := time.Now()
	for p, pstats := range ps.peerStats {
		if !pstats.connected {
			// has the retention period expired?
			if now.After(pstats.expire) {
				// yes, throw it away (but clean up the IP tracking first)
				ps.removeIPs(p, pstats.ips)
				delete(ps.peerStats, p)
			}

			// we don't decay retained scores, as the peer is not active.
			// this way the peer cannot reset a negative score by simply disconnecting and reconnecting,
			// unless the retention period has ellapsed.
			// similarly, a well behaved peer does not lose its score by getting disconnected.
			continue
		}

		for bitmask, tstats := range pstats.bitmasks {
			// the bitmask parameters
			bitmaskParams, ok := ps.params.Bitmasks[string(bitmask)]
			if !ok {
				// we are not scoring this bitmask
				continue
			}

			// decay counters
			tstats.firstMessageDeliveries *= bitmaskParams.FirstMessageDeliveriesDecay
			if tstats.firstMessageDeliveries < ps.params.DecayToZero {
				tstats.firstMessageDeliveries = 0
			}
			tstats.meshMessageDeliveries *= bitmaskParams.MeshMessageDeliveriesDecay
			if tstats.meshMessageDeliveries < ps.params.DecayToZero {
				tstats.meshMessageDeliveries = 0
			}
			tstats.meshFailurePenalty *= bitmaskParams.MeshFailurePenaltyDecay
			if tstats.meshFailurePenalty < ps.params.DecayToZero {
				tstats.meshFailurePenalty = 0
			}
			tstats.invalidMessageDeliveries *= bitmaskParams.InvalidMessageDeliveriesDecay
			if tstats.invalidMessageDeliveries < ps.params.DecayToZero {
				tstats.invalidMessageDeliveries = 0
			}
			// update mesh time and activate mesh message delivery parameter if need be
			if tstats.inMesh {
				tstats.meshTime = now.Sub(tstats.graftTime)
				if tstats.meshTime > bitmaskParams.MeshMessageDeliveriesActivation {
					tstats.meshMessageDeliveriesActive = true
				}
			}
		}

		// decay P7 counter
		pstats.behaviourPenalty *= ps.params.BehaviourPenaltyDecay
		if pstats.behaviourPenalty < ps.params.DecayToZero {
			pstats.behaviourPenalty = 0
		}
	}

	ps.Unlock()
}

// refreshIPs refreshes IPs we know of peers we're tracking.
func (ps *peerScore) refreshIPs() {
	ps.Lock()

	// peer IPs may change, so we periodically refresh them
	//
	// TODO: it could be more efficient to collect connections for all peers
	// from the Network, populate a new map, and replace it in place. We are
	// incurring in those allocs anyway, and maybe even in more, in the form of
	// slices.
	for p, pstats := range ps.peerStats {
		if pstats.connected {
			ips := ps.getIPs(p)
			ps.setIPs(p, ips, pstats.ips)
			pstats.ips = ips
		}
	}

	ps.Unlock()
}

func (ps *peerScore) gcDeliveryRecords() {
	ps.Lock()

	ps.deliveries.gc()
	ps.Unlock()
}

// tracer interface
func (ps *peerScore) AddPeer(p peer.ID, proto protocol.ID) {
	ps.Lock()

	pstats, ok := ps.peerStats[p]
	if !ok {
		pstats = &peerStats{bitmasks: make(map[string]*bitmaskStats)}
		ps.peerStats[p] = pstats
	}

	pstats.connected = true
	ips := ps.getIPs(p)
	ps.setIPs(p, ips, pstats.ips)
	pstats.ips = ips
	ps.Unlock()
}

func (ps *peerScore) RemovePeer(p peer.ID) {
	ps.Lock()

	pstats, ok := ps.peerStats[p]
	if !ok {
		ps.Unlock()
		return
	}

	// decide whether to retain the score; this currently only retains non-positive scores
	// to dissuade attacks on the score function.
	if ps.score(p) > 0 {
		ps.removeIPs(p, pstats.ips)
		delete(ps.peerStats, p)
		ps.Unlock()
		return
	}

	// furthermore, when we decide to retain the score, the firstMessageDelivery counters are
	// reset to 0 and mesh delivery penalties applied.
	for bitmask, tstats := range pstats.bitmasks {
		tstats.firstMessageDeliveries = 0

		threshold := ps.params.Bitmasks[string(bitmask)].MeshMessageDeliveriesThreshold
		if tstats.inMesh && tstats.meshMessageDeliveriesActive && tstats.meshMessageDeliveries < threshold {
			deficit := threshold - tstats.meshMessageDeliveries
			tstats.meshFailurePenalty += deficit * deficit
		}

		tstats.inMesh = false
	}

	pstats.connected = false
	pstats.expire = time.Now().Add(ps.params.RetainScore)
	ps.Unlock()
}

func (ps *peerScore) Join(bitmask []byte)  {}
func (ps *peerScore) Leave(bitmask []byte) {}

func (ps *peerScore) Graft(p peer.ID, bitmask []byte) {
	ps.Lock()

	pstats, ok := ps.peerStats[p]
	if !ok {
		ps.Unlock()
		return
	}

	tstats, ok := pstats.getBitmaskStats(bitmask, ps.params)
	if !ok {
		ps.Unlock()
		return
	}

	tstats.inMesh = true
	tstats.graftTime = time.Now()
	tstats.meshTime = 0
	tstats.meshMessageDeliveriesActive = false
	ps.Unlock()
}

func (ps *peerScore) Prune(p peer.ID, bitmask []byte) {
	ps.Lock()

	pstats, ok := ps.peerStats[p]
	if !ok {
		ps.Unlock()
		return
	}

	tstats, ok := pstats.getBitmaskStats(bitmask, ps.params)
	if !ok {
		ps.Unlock()
		return
	}

	// sticky mesh delivery rate failure penalty
	threshold := ps.params.Bitmasks[string(bitmask)].MeshMessageDeliveriesThreshold
	if tstats.meshMessageDeliveriesActive && tstats.meshMessageDeliveries < threshold {
		deficit := threshold - tstats.meshMessageDeliveries
		tstats.meshFailurePenalty += deficit * deficit
	}

	tstats.inMesh = false
	ps.Unlock()
}

func (ps *peerScore) ValidateMessage(msg *Message) {
	ps.Lock()

	// the pubsub subsystem is beginning validation; create a record to track time in
	// the validation pipeline with an accurate firstSeen time.
	_ = ps.deliveries.getRecord(ps.idGen.ID(msg))
	ps.Unlock()
}

func (ps *peerScore) DeliverMessage(msg *Message) {
	ps.Lock()

	ps.markFirstMessageDelivery(msg.ReceivedFrom, msg)

	drec := ps.deliveries.getRecord(ps.idGen.ID(msg))

	// defensive check that this is the first delivery trace -- delivery status should be unknown
	if drec.status != deliveryUnknown {
		log.Debugf("unexpected delivery trace: message from %s was first seen %s ago and has delivery status %d", msg.ReceivedFrom, time.Since(drec.firstSeen), drec.status)
		ps.Unlock()
		return
	}

	// mark the message as valid and reward mesh peers that have already forwarded it to us
	drec.status = deliveryValid
	drec.validated = time.Now()
	for p := range drec.peers {
		// this check is to make sure a peer can't send us a message twice and get a double count
		// if it is a first delivery.
		if p != msg.ReceivedFrom {
			ps.markDuplicateMessageDelivery(p, msg, time.Time{})
		}
	}
	ps.Unlock()
}

func (ps *peerScore) RejectMessage(msg *Message, reason string) {
	ps.Lock()

	switch reason {
	// we don't track those messages, but we penalize the peer as they are clearly invalid
	case RejectMissingSignature:
		fallthrough
	case RejectInvalidSignature:
		fallthrough
	case RejectUnexpectedSignature:
		fallthrough
	case RejectUnexpectedAuthInfo:
		fallthrough
	case RejectSelfOrigin:
		ps.markInvalidMessageDelivery(msg.ReceivedFrom, msg)
		ps.Unlock()
		return

		// we ignore those messages, so do nothing.
	case RejectBlacklstedPeer:
		fallthrough
	case RejectBlacklistedSource:
		ps.Unlock()
		return

	case RejectValidationQueueFull:
		// the message was rejected before it entered the validation pipeline;
		// we don't know if this message has a valid signature, and thus we also don't know if
		// it has a valid message ID; all we can do is ignore it.
		ps.Unlock()
		return
	}

	drec := ps.deliveries.getRecord(ps.idGen.ID(msg))

	// defensive check that this is the first rejection trace -- delivery status should be unknown
	if drec.status != deliveryUnknown {
		log.Debugf("unexpected rejection trace: message from %s was first seen %s ago and has delivery status %d", msg.ReceivedFrom, time.Since(drec.firstSeen), drec.status)
		ps.Unlock()
		return
	}

	switch reason {
	case RejectValidationThrottled:
		// if we reject with "validation throttled" we don't penalize the peer(s) that forward it
		// because we don't know if it was valid.
		drec.status = deliveryThrottled
		// release the delivery time tracking map to free some memory early
		drec.peers = nil
		ps.Unlock()
		return
	case RejectValidationIgnored:
		// we were explicitly instructed by the validator to ignore the message but not penalize
		// the peer
		drec.status = deliveryIgnored
		drec.peers = nil
		ps.Unlock()
		return
	}

	// mark the message as invalid and penalize peers that have already forwarded it.
	drec.status = deliveryInvalid

	ps.markInvalidMessageDelivery(msg.ReceivedFrom, msg)
	for p := range drec.peers {
		ps.markInvalidMessageDelivery(p, msg)
	}

	// release the delivery time tracking map to free some memory early
	drec.peers = nil
	ps.Unlock()
}

func (ps *peerScore) DuplicateMessage(msg *Message) {
	ps.Lock()

	drec := ps.deliveries.getRecord(ps.idGen.ID(msg))

	_, ok := drec.peers[msg.ReceivedFrom]
	if ok {
		// we have already seen this duplicate!
		ps.Unlock()
		return
	}

	switch drec.status {
	case deliveryUnknown:
		// the message is being validated; track the peer delivery and wait for
		// the Deliver/Reject notification.
		drec.peers[msg.ReceivedFrom] = struct{}{}

	case deliveryValid:
		// mark the peer delivery time to only count a duplicate delivery once.
		drec.peers[msg.ReceivedFrom] = struct{}{}
		ps.markDuplicateMessageDelivery(msg.ReceivedFrom, msg, drec.validated)

	case deliveryInvalid:
		// we no longer track delivery time
		ps.markInvalidMessageDelivery(msg.ReceivedFrom, msg)

	case deliveryThrottled:
		// the message was throttled; do nothing (we don't know if it was valid)
	case deliveryIgnored:
		// the message was ignored; do nothing
	}
	ps.Unlock()
}

func (ps *peerScore) ThrottlePeer(p peer.ID) {}

func (ps *peerScore) RecvRPC(rpc *RPC) {}

func (ps *peerScore) SendRPC(rpc *RPC, p peer.ID) {}

func (ps *peerScore) DropRPC(rpc *RPC, p peer.ID) {}

func (ps *peerScore) UndeliverableMessage(msg *Message) {}

// message delivery records
func (d *messageDeliveries) getRecord(id []byte) *deliveryRecord {
	rec, ok := d.records[string(id)]
	if ok {
		return rec
	}

	now := time.Now()

	rec = &deliveryRecord{peers: make(map[peer.ID]struct{}), firstSeen: now}
	d.records[string(id)] = rec

	entry := &deliveryEntry{id: id, expire: now.Add(d.seenMsgTTL)}
	if d.tail != nil {
		d.tail.next = entry
		d.tail = entry
	} else {
		d.head = entry
		d.tail = entry
	}

	return rec
}

func (d *messageDeliveries) gc() {
	if d.head == nil {
		return
	}

	now := time.Now()
	for d.head != nil && now.After(d.head.expire) {
		delete(d.records, string(d.head.id))
		d.head = d.head.next
	}

	if d.head == nil {
		d.tail = nil
	}
}

// getBitmaskStats returns existing bitmask stats for a given a given (peer, bitmask)
// tuple, or initialises a new bitmaskStats object and inserts it in the
// peerStats, iff the bitmask is scored.
func (pstats *peerStats) getBitmaskStats(bitmask []byte, params *PeerScoreParams) (*bitmaskStats, bool) {
	tstats, ok := pstats.bitmasks[string(bitmask)]
	if ok {
		return tstats, true
	}

	_, scoredBitmask := params.Bitmasks[string(bitmask)]
	if !scoredBitmask {
		return nil, false
	}

	tstats = &bitmaskStats{}
	pstats.bitmasks[string(bitmask)] = tstats

	return tstats, true
}

// markInvalidMessageDelivery increments the "invalid message deliveries"
// counter for all scored bitmasks the message is published in.
func (ps *peerScore) markInvalidMessageDelivery(p peer.ID, msg *Message) {
	pstats, ok := ps.peerStats[p]
	if !ok {
		return
	}

	bitmask := msg.GetBitmask()
	tstats, ok := pstats.getBitmaskStats(bitmask, ps.params)
	if !ok {
		return
	}

	tstats.invalidMessageDeliveries += 1
}

// markFirstMessageDelivery increments the "first message deliveries" counter
// for all scored bitmasks the message is published in, as well as the "mesh
// message deliveries" counter, if the peer is in the mesh for the bitmask.
func (ps *peerScore) markFirstMessageDelivery(p peer.ID, msg *Message) {
	pstats, ok := ps.peerStats[p]
	if !ok {
		return
	}

	bitmask := msg.GetBitmask()
	tstats, ok := pstats.getBitmaskStats(bitmask, ps.params)
	if !ok {
		return
	}

	cap := ps.params.Bitmasks[string(bitmask)].FirstMessageDeliveriesCap
	tstats.firstMessageDeliveries += 1
	if tstats.firstMessageDeliveries > cap {
		tstats.firstMessageDeliveries = cap
	}

	if !tstats.inMesh {
		return
	}

	cap = ps.params.Bitmasks[string(bitmask)].MeshMessageDeliveriesCap
	tstats.meshMessageDeliveries += 1
	if tstats.meshMessageDeliveries > cap {
		tstats.meshMessageDeliveries = cap
	}
}

// markDuplicateMessageDelivery increments the "mesh message deliveries" counter
// for messages we've seen before, as long the message was received within the
// P3 window.
func (ps *peerScore) markDuplicateMessageDelivery(p peer.ID, msg *Message, validated time.Time) {
	pstats, ok := ps.peerStats[p]
	if !ok {
		return
	}

	bitmask := msg.GetBitmask()
	tstats, ok := pstats.getBitmaskStats(bitmask, ps.params)
	if !ok {
		return
	}

	if !tstats.inMesh {
		return
	}

	tparams := ps.params.Bitmasks[string(bitmask)]

	// check against the mesh delivery window -- if the validated time is passed as 0, then
	// the message was received before we finished validation and thus falls within the mesh
	// delivery window.
	if !validated.IsZero() && time.Since(validated) > tparams.MeshMessageDeliveriesWindow {
		return
	}

	cap := tparams.MeshMessageDeliveriesCap
	tstats.meshMessageDeliveries += 1
	if tstats.meshMessageDeliveries > cap {
		tstats.meshMessageDeliveries = cap
	}
}

// getIPs gets the current IPs for a peer.
func (ps *peerScore) getIPs(p peer.ID) []string {
	// in unit tests this can be nil
	if ps.host == nil {
		return nil
	}

	conns := ps.host.Network().ConnsToPeer(p)
	res := make([]string, 0, 1)
	for _, c := range conns {
		if c.Stat().Limited {
			// ignore transient
			continue
		}

		remote := c.RemoteMultiaddr()
		ip, err := manet.ToIP(remote)
		if err != nil {
			continue
		}

		// ignore those; loopback is used for unit testing
		if ip.IsLoopback() {
			continue
		}

		if len(ip.To4()) == 4 {
			// IPv4 address
			ip4 := ip.String()
			res = append(res, ip4)
		} else {
			// IPv6 address -- we add both the actual address and the /64 subnet
			ip6 := ip.String()
			res = append(res, ip6)

			ip6mask := ip.Mask(net.CIDRMask(64, 128)).String()
			res = append(res, ip6mask)
		}
	}

	return res
}

// setIPs adds tracking for the new IPs in the list, and removes tracking from
// the obsolete IPs.
func (ps *peerScore) setIPs(p peer.ID, newips, oldips []string) {
addNewIPs:
	// add the new IPs to the tracking
	for _, ip := range newips {
		// check if it is in the old ips list
		for _, xip := range oldips {
			if ip == xip {
				continue addNewIPs
			}
		}
		// no, it's a new one -- add it to the tracker
		peers, ok := ps.peerIPs[ip]
		if !ok {
			peers = make(map[peer.ID]struct{})
			ps.peerIPs[ip] = peers
		}
		peers[p] = struct{}{}
	}

removeOldIPs:
	// remove the obsolete old IPs from the tracking
	for _, ip := range oldips {
		// check if it is in the new ips list
		for _, xip := range newips {
			if ip == xip {
				continue removeOldIPs
			}
		}
		// no, it's obsolete -- remove it from the tracker
		peers, ok := ps.peerIPs[ip]
		if !ok {
			continue
		}
		delete(peers, p)
		if len(peers) == 0 {
			delete(ps.peerIPs, ip)
		}
	}
}

// removeIPs removes an IP list from the tracking list for a peer.
func (ps *peerScore) removeIPs(p peer.ID, ips []string) {
	for _, ip := range ips {
		peers, ok := ps.peerIPs[ip]
		if !ok {
			continue
		}

		delete(peers, p)
		if len(peers) == 0 {
			delete(ps.peerIPs, ip)
		}
	}
}
