package application

import (
	"encoding/binary"
	"errors"

	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

type AtomType string
type Location [64]byte // 32 bytes for AppAddress + 32 bytes for DataAddress

var ErrInvalidAtomType = errors.New("invalid atom type for set")
var ErrInvalidLocation = errors.New("invalid location")
var ErrMissingExtrinsics = errors.New("missing extrinsics")
var ErrIsExtrinsic = errors.New("is extrinsic")

type Vertex struct {
	AppAddress   [32]byte
	DataAddress  [32]byte
	SegmentOrder uint16
}

type Hyperedge struct {
	AppAddress  [32]byte
	DataAddress [32]byte
	Index       uint16
	Extrinsics  map[[66]byte]Atom
}

type Atom interface {
	GetID() [66]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
}

func (v *Vertex) GetID() [66]byte {
	id := [66]byte{}
	copy(id[:32], v.AppAddress[:])
	copy(id[32:64], v.DataAddress[:])
	binary.BigEndian.PutUint16(id[64:], v.SegmentOrder)
	return id
}

func (v *Vertex) GetAtomType() AtomType {
	return "vertex"
}

func (v *Vertex) GetLocation() Location {
	var loc Location
	copy(loc[:32], v.AppAddress[:])
	copy(loc[32:], v.DataAddress[:])
	return loc
}

func (v *Vertex) GetAppAddress() [32]byte {
	return v.AppAddress
}

func (v *Vertex) GetDataAddress() [32]byte {
	return v.DataAddress
}

func (h *Hyperedge) GetID() [66]byte {
	id := [66]byte{}
	copy(id[:32], h.AppAddress[:])
	copy(id[32:], h.DataAddress[:])
	binary.BigEndian.PutUint16(id[64:], h.Index)
	return id
}

func (h *Hyperedge) GetAtomType() AtomType {
	return "hyperedge"
}

func (h *Hyperedge) GetLocation() Location {
	var loc Location
	copy(loc[:32], h.AppAddress[:])
	copy(loc[32:], h.DataAddress[:])
	return loc
}

func (h *Hyperedge) GetAppAddress() [32]byte {
	return h.AppAddress
}

func (h *Hyperedge) GetDataAddress() [32]byte {
	return h.DataAddress
}

type ShardAddress struct {
	L1 [3]byte
	L2 [48]byte
}

func GetShardAddress(a Atom) ShardAddress {
	appAddress := a.GetAppAddress()
	dataAddress := a.GetDataAddress()

	return ShardAddress{
		L1: [3]byte(p2p.GetBloomFilterIndices(appAddress[:], 256, 3)),
		L2: [48]byte(p2p.GetBloomFilterIndices(append(append([]byte{}, appAddress[:]...), dataAddress[:]...), 65536, 24)),
	}
}

type IdSet struct {
	atomType AtomType
	atoms    map[[66]byte]Atom
}

func NewIdSet(atomType AtomType) *IdSet {
	return &IdSet{atomType: atomType, atoms: make(map[[66]byte]Atom)}
}

func (set *IdSet) Add(atom Atom) error {
	if atom.GetAtomType() != set.atomType {
		return ErrInvalidAtomType
	}
	if _, exists := set.atoms[atom.GetID()]; !exists {
		set.atoms[atom.GetID()] = atom
	}
	return nil
}

func (set *IdSet) Delete(atom Atom) bool {
	if _, exists := set.atoms[atom.GetID()]; exists {
		delete(set.atoms, atom.GetID())
		return true
	}
	return false
}

func (set *IdSet) Has(atom Atom) bool {
	_, exists := set.atoms[atom.GetID()]
	return exists
}

type Hypergraph struct {
	vertexAdds       map[ShardAddress]*IdSet
	vertexRemoves    map[ShardAddress]*IdSet
	hyperedgeAdds    map[ShardAddress]*IdSet
	hyperedgeRemoves map[ShardAddress]*IdSet
}

func NewHypergraph() *Hypergraph {
	return &Hypergraph{
		vertexAdds:       make(map[ShardAddress]*IdSet),
		vertexRemoves:    make(map[ShardAddress]*IdSet),
		hyperedgeAdds:    make(map[ShardAddress]*IdSet),
		hyperedgeRemoves: make(map[ShardAddress]*IdSet),
	}
}

func (hg *Hypergraph) getOrCreateIdSet(shardAddr ShardAddress, addMap map[ShardAddress]*IdSet, removeMap map[ShardAddress]*IdSet, atomType AtomType) (*IdSet, *IdSet) {
	if _, ok := addMap[shardAddr]; !ok {
		addMap[shardAddr] = NewIdSet(atomType)
	}
	if _, ok := removeMap[shardAddr]; !ok {
		removeMap[shardAddr] = NewIdSet(atomType)
	}
	return addMap[shardAddr], removeMap[shardAddr]
}

func (hg *Hypergraph) AddVertex(v *Vertex) error {
	shardAddr := GetShardAddress(v)
	addSet, _ := hg.getOrCreateIdSet(shardAddr, hg.vertexAdds, hg.vertexRemoves, "vertex")
	return addSet.Add(v)
}

func (hg *Hypergraph) AddHyperedge(h *Hyperedge) error {
	if !hg.LookupAtomSet(h.Extrinsics) {
		return ErrMissingExtrinsics
	}
	shardAddr := GetShardAddress(h)
	addSet, _ := hg.getOrCreateIdSet(shardAddr, hg.hyperedgeAdds, hg.hyperedgeRemoves, "hyperedge")
	return addSet.Add(h)
}

func (hg *Hypergraph) RemoveVertex(v *Vertex) error {
	shardAddr := GetShardAddress(v)

	if !hg.LookupVertex(v) {
		_, removeSet := hg.getOrCreateIdSet(shardAddr, hg.vertexAdds, hg.vertexRemoves, "vertex")
		return removeSet.Add(v)
	}

	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*Hyperedge); ok {
				if _, ok := he.Extrinsics[v.GetID()]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(shardAddr, hg.vertexAdds, hg.vertexRemoves, "vertex")
	return removeSet.Add(v)
}

func (hg *Hypergraph) RemoveHyperedge(h *Hyperedge) error {
	shardAddr := GetShardAddress(h)

	if !hg.LookupHyperedge(h) {
		_, removeSet := hg.getOrCreateIdSet(shardAddr, hg.hyperedgeAdds, hg.hyperedgeRemoves, "hyperedge")
		return removeSet.Add(h)
	}

	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*Hyperedge); ok {
				if _, ok := he.Extrinsics[h.GetID()]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(shardAddr, hg.hyperedgeAdds, hg.hyperedgeRemoves, "hyperedge")
	return removeSet.Add(h)
}

func (hg *Hypergraph) LookupVertex(v *Vertex) bool {
	shardAddr := GetShardAddress(v)
	addSet, removeSet := hg.getOrCreateIdSet(shardAddr, hg.vertexAdds, hg.vertexRemoves, "vertex")
	return addSet.Has(v) && !removeSet.Has(v)
}

func (hg *Hypergraph) LookupHyperedge(h *Hyperedge) bool {
	shardAddr := GetShardAddress(h)
	addSet, removeSet := hg.getOrCreateIdSet(shardAddr, hg.hyperedgeAdds, hg.hyperedgeRemoves, "hyperedge")
	return hg.LookupAtomSet(h.Extrinsics) && addSet.Has(h) && !removeSet.Has(h)
}

func (hg *Hypergraph) LookupAtom(a Atom) bool {
	switch v := a.(type) {
	case *Vertex:
		return hg.LookupVertex(v)
	case *Hyperedge:
		return hg.LookupHyperedge(v)
	default:
		return false
	}
}

func (hg *Hypergraph) LookupAtomSet(atomSet map[[66]byte]Atom) bool {
	for _, atom := range atomSet {
		if !hg.LookupAtom(atom) {
			return false
		}
	}
	return true
}

func (hg *Hypergraph) Within(a, h Atom) bool {
	if he, ok := h.(*Hyperedge); ok {
		if _, ok := he.Extrinsics[a.GetID()]; ok || a.GetID() == h.GetID() {
			return true
		}
		for _, extrinsic := range he.Extrinsics {
			if nestedHe, ok := extrinsic.(*Hyperedge); ok {
				if hg.LookupHyperedge(nestedHe) && hg.Within(a, nestedHe) {
					return true
				}
			}
		}
	}
	return false
}

// GetReconciledVertexSetForShard computes the set of vertices that have been added but
// not removed for a specific shard.
func (hg *Hypergraph) GetReconciledVertexSetForShard(shardAddr ShardAddress) *IdSet {
	vertices := NewIdSet("vertex")

	if addSet, ok := hg.vertexAdds[shardAddr]; ok {
		removeSet := hg.vertexRemoves[shardAddr]
		for _, v := range addSet.atoms {
			if !removeSet.Has(v) {
				vertices.Add(v)
			}
		}
	}

	return vertices
}

// GetReconciledHyperedgeSetForShard computes the set of hyperedges that have been added
// but not removed for a specific shard.
func (hg *Hypergraph) GetReconciledHyperedgeSetForShard(shardAddr ShardAddress) *IdSet {
	hyperedges := NewIdSet("hyperedge")

	if addSet, ok := hg.hyperedgeAdds[shardAddr]; ok {
		removeSet := hg.hyperedgeRemoves[shardAddr]
		for _, h := range addSet.atoms {
			if !removeSet.Has(h) {
				hyperedges.Add(h)
			}
		}
	}

	return hyperedges
}
