package tries

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type Node struct {
	Internal *InternalNode
	External *ExternalNode
}

type InternalNode struct {
	Child      [2]Node
	ByteNumber uint32
	Bits       byte
}

type ExternalNode struct {
	Key           []byte
	EarliestFrame uint64
	LatestFrame   uint64
	Count         uint64
}

type RollingFrecencyCritbitTrie struct {
	Root *Node
	mu   sync.RWMutex
}

func (t *RollingFrecencyCritbitTrie) Serialize() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(t.Root); err != nil {
		return nil, errors.Wrap(err, "serialize")
	}

	return b.Bytes(), nil
}

func (t *RollingFrecencyCritbitTrie) Deserialize(buf []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b bytes.Buffer
	b.Write(buf)
	dec := gob.NewDecoder(&b)

	if err := dec.Decode(&t.Root); err != nil {
		return errors.Wrap(err, "deserialize")
	}

	return nil
}

func (t *RollingFrecencyCritbitTrie) Contains(address []byte) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.findNearest(address)
	return p != nil &&
		p.External != nil &&
		bytes.Equal(p.External.Key, address)
}

func (t *RollingFrecencyCritbitTrie) Get(
	address []byte,
) (earliestFrame uint64, latestFrame uint64, count uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.findNearest(address)

	if p != nil &&
		p.External != nil &&
		bytes.Equal(p.External.Key, address) {
		return p.External.EarliestFrame, p.External.LatestFrame, p.External.Count
	}

	return 0, 0, 0
}

func (t *RollingFrecencyCritbitTrie) FindNearest(
	address []byte,
) *Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.findNearest(address)
}

func (t *RollingFrecencyCritbitTrie) findNearest(
	address []byte,
) *Node {
	blen := uint32(len(address))
	p := t.Root

	if p == nil {
		return nil
	}

	for p.Internal != nil {
		right := p.Internal.ByteNumber < blen &&
			address[p.Internal.ByteNumber]&p.Internal.Bits != 0
		if right {
			p = &p.Internal.Child[1]
		} else {
			p = &p.Internal.Child[0]
		}
	}

	return p
}

func (t *RollingFrecencyCritbitTrie) FindNearestAndApproximateNeighbors(
	address []byte,
) []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	blen := uint32(len(address))
	if t.Root == nil {
		return nil
	}

	ret := []*Node{}

	var traverse func(p *Node, address []byte) bool
	traverse = func(p *Node, address []byte) bool {
		if len(ret) > 256 {
			return true
		}

		if p.Internal != nil {
			right := p.Internal.ByteNumber < blen &&
				address[p.Internal.ByteNumber]&p.Internal.Bits != 0

			if right && !traverse(&p.Internal.Child[1], address) ||
				!traverse(&p.Internal.Child[0], address) {
				return false
			}

			if !right {
				return traverse(&p.Internal.Child[1], address)
			}

			return true
		} else {
			ret = append(ret, p)
			return true
		}
	}

	traverse(t.Root, address)
	base := new(big.Int)
	base.SetBytes(address)

	sort.Slice(ret, func(i, j int) bool {
		bi, bj := new(big.Int), new(big.Int)
		bi.SetBytes(ret[i].External.Key)
		bj.SetBytes(ret[j].External.Key)

		bi.Sub(base, bi)
		bj.Sub(base, bj)

		return bi.CmpAbs(bj) <= 0
	})

	return ret
}

func (t *RollingFrecencyCritbitTrie) Add(
	address []byte,
	latestFrame uint64,
) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Root == nil {
		t.Root = &Node{
			External: &ExternalNode{
				Key:           address,
				EarliestFrame: latestFrame,
				LatestFrame:   latestFrame,
				Count:         1,
			},
		}
		return
	}

	p := t.findNearest(address)
	byteNumber, bits := p.critBit(address)
	if byteNumber < 0 {
		if p.External.LatestFrame < latestFrame {
			p.External.LatestFrame = latestFrame
		}
		if p.External.EarliestFrame > latestFrame {
			p.External.EarliestFrame = latestFrame
		}
		p.External.Count++
		return
	}

	node := &InternalNode{
		ByteNumber: uint32(byteNumber),
		Bits:       bits,
	}

	blen := uint32(len(address))
	right := node.ByteNumber < blen &&
		address[node.ByteNumber]&node.Bits != 0
	e := &ExternalNode{
		Key:           address,
		EarliestFrame: latestFrame,
		LatestFrame:   latestFrame,
		Count:         1,
	}
	if right {
		node.Child[1].External = e
	} else {
		node.Child[0].External = e
	}

	p = t.Root
	for m := p.Internal; m != nil; m = p.Internal {
		if m.ByteNumber > uint32(byteNumber) ||
			m.ByteNumber == uint32(byteNumber) && m.Bits < bits {
			break
		}

		if m.ByteNumber < blen && address[m.ByteNumber]&m.Bits != 0 {
			p = &m.Child[1]
		} else {
			p = &m.Child[0]
		}
	}

	if p.Internal != nil {
		// inverse the direction
		if right {
			node.Child[0].Internal = p.Internal
		} else {
			node.Child[1].Internal = p.Internal
		}
	} else {
		if right {
			node.Child[0].External = p.External
		} else {
			node.Child[1].External = p.External
			p.External = nil
		}
	}

	p.Internal = node
}

func (t *RollingFrecencyCritbitTrie) Remove(address []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Root == nil {
		return
	}

	blen := uint32(len(address))
	var gp *Node
	p := t.Root
	var right bool

	for m := p.Internal; m != nil; m = p.Internal {
		right = p.Internal.ByteNumber < blen &&
			address[p.Internal.ByteNumber]&p.Internal.Bits != 0
		if right {
			gp, p = p, &m.Child[1]
		} else {
			gp, p = p, &m.Child[0]
		}
	}

	if !bytes.Equal(p.External.Key, address) {
		return
	}

	if gp == nil {
		p.External = nil
	} else {
		if right {
			gp.External, gp.Internal = gp.Internal.Child[0].External,
				gp.Internal.Child[0].Internal
		} else {
			gp.External, gp.Internal = gp.Internal.Child[1].External,
				gp.Internal.Child[1].Internal
		}
	}
}

func (n *Node) String() string {
	if n.External != nil {
		return hex.EncodeToString(n.External.Key)
	} else {
		nodes := []string{}
		for i := range n.Internal.Child {
			nodes = append(nodes, n.Internal.Child[i].String())
		}
		return strings.Join(nodes, ",")
	}
}

func (n *Node) Bits() []byte {
	if n.External != nil {
		return n.External.Key
	} else {
		return nil
	}
}

func (n *Node) Info() (latestFrame uint64, count uint64) {
	if n.External != nil {
		return n.External.LatestFrame, n.External.Count
	} else {
		return 0, 0
	}
}

func (n *Node) critBit(
	address []byte,
) (byteNumber int, bits byte) {
	smallestLen := len(n.External.Key)
	if len(address) < smallestLen {
		smallestLen = len(address)
	}

	for byteNumber = 0; byteNumber < smallestLen; byteNumber++ {
		if l, r := address[byteNumber], n.External.Key[byteNumber]; l != r {
			b := l ^ r
			b |= b >> 1
			b |= b >> 2
			b |= b >> 4
			bits = b &^ (b >> 1)
			return
		}
	}

	if len(n.External.Key) < len(address) {
		b := address[byteNumber]
		b |= b >> 1
		b |= b >> 2
		b |= b >> 4
		bits = b &^ (b >> 1)
	} else if len(n.External.Key) > len(address) {
		b := n.External.Key[byteNumber]
		b |= b >> 1
		b |= b >> 2
		b |= b >> 4
		bits = b &^ (b >> 1)
	} else {
		byteNumber = -1
	}
	return
}
