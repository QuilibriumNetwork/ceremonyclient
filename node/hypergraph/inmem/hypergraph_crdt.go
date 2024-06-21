package inmem

import "errors"

var ErrInvalidLocation error = errors.New("invalid location")
var ErrMissingExtrinsics error = errors.New("missing extrinsics")
var ErrIsExtrinsic error = errors.New("is extrinsic")

type HypergraphCRDT struct {
	locations map[Location]struct{}

	vertexAdds       map[Location]*IdSet
	vertexRemoves    map[Location]*IdSet
	hyperedgeAdds    map[Location]*IdSet
	hyperedgeRemoves map[Location]*IdSet
}

func NewHypergraphCRDT(locations []Location) *HypergraphCRDT {
	hypergraph := &HypergraphCRDT{
		locations:        make(map[Location]struct{}),
		vertexAdds:       make(map[Location]*IdSet),
		vertexRemoves:    make(map[Location]*IdSet),
		hyperedgeAdds:    make(map[Location]*IdSet),
		hyperedgeRemoves: make(map[Location]*IdSet),
	}

	for _, l := range locations {
		hypergraph.locations[l] = struct{}{}
		hypergraph.vertexAdds[l] = NewIdSet("vertex")
		hypergraph.vertexRemoves[l] = NewIdSet("vertex")
		hypergraph.hyperedgeAdds[l] = NewIdSet("hyperedge")
		hypergraph.hyperedgeRemoves[l] = NewIdSet("hyperedge")
	}

	return hypergraph
}

func (hg *HypergraphCRDT) AddAtom(a Atom) error {
	switch v := a.(type) {
	case *Vertex:
		hg.AddVertex(v)
		return nil
	case *Hyperedge:
		return hg.AddHyperedge(v)
	}

	return nil
}

func (hg *HypergraphCRDT) AddVertex(v *Vertex) {
	shardMap := ShardVertex(v)
	for location, vertices := range shardMap {
		for _, vertex := range vertices.VertexSet.atoms {
			if vert, ok := vertex.(*Vertex); ok {
				hg.vertexAdds[location].Add(vert)
			}
		}
	}
}

func (hg *HypergraphCRDT) AddVertexSet(vertices *IdSet) error {
	if vertices.atomType != "vertex" {
		return ErrInvalidAtomType
	}

	shardMap := ShardAtomSet(vertices.atoms)
	for location, vertices := range shardMap {
		for _, vertex := range vertices.VertexSet.atoms {
			if vert, ok := vertex.(*Vertex); ok {
				hg.vertexAdds[location].Add(vert)
			}
		}
	}

	return nil
}

func (hg *HypergraphCRDT) AddHyperedge(h *Hyperedge) error {
	if hg.LookupAtomSet(h.extrinsics) {
		shardMap := ShardHyperedge(h)

		for location, set := range shardMap {
			for _, hyperedge := range set.HyperedgeSet.atoms {
				if he, ok := hyperedge.(*Hyperedge); ok {
					hg.hyperedgeAdds[location].Add(he)
				}
			}
			for _, vertex := range set.VertexSet.atoms {
				if v, ok := vertex.(*Vertex); ok {
					hg.hyperedgeAdds[location].Add(v)
				}
			}
		}

		return nil
	} else {
		return ErrMissingExtrinsics
	}
}

func (hg *HypergraphCRDT) RemoveAtom(a Atom) error {
	switch v := a.(type) {
	case *Vertex:
		return hg.RemoveVertex(v)
	case *Hyperedge:
		return hg.RemoveHyperedge(v)
	}

	return nil
}

func (hg *HypergraphCRDT) RemoveVertex(v *Vertex) error {
	if hg.LookupVertex(v) {
		for l, hyperedgeAdds := range hg.hyperedgeAdds {
			for _, hyperedge := range hyperedgeAdds.atoms {
				he, ok := hyperedge.(*Hyperedge)
				if !ok {
					continue
				}
				if !hg.hyperedgeRemoves[l].Has(he) {
					if _, ok := he.extrinsics[v.GetID()]; ok {
						return ErrIsExtrinsic
					}
				}
			}
		}

		hg.vertexRemoves[v.location].Add(v)
	}

	return nil
}

func (hg *HypergraphCRDT) RemoveHyperedge(h *Hyperedge) error {
	if hg.LookupAtom(h) {
		for l, hyperedgeAdds := range hg.hyperedgeAdds {
			for _, hyperedge := range hyperedgeAdds.atoms {
				he, ok := hyperedge.(*Hyperedge)
				if !ok || hg.hyperedgeRemoves[l].Has(he) {
					continue
				}
				if _, ok := he.extrinsics[h.GetID()]; ok {
					return ErrIsExtrinsic
				}
			}
		}

		hg.hyperedgeRemoves[h.location].Add(h)
	}

	return nil
}

func (hg *HypergraphCRDT) LookupAtom(a Atom) bool {
	if _, ok := hg.locations[a.GetLocation()]; !ok {
		return false
	}

	switch v := a.(type) {
	case *Vertex:
		return hg.LookupVertex(v)
	case *Hyperedge:
		return hg.LookupHyperedge(v)
	default:
		return false
	}
}

// LookupAtomSet checks all atoms in an IdSet to see if they all can be looked
// up successfully.
func (hg *HypergraphCRDT) LookupAtomSet(atomSet map[string]Atom) bool {
	for _, atom := range atomSet {
		if !hg.LookupAtom(atom) {
			return false
		}
	}
	return true
}

// LookupVertex checks if a vertex is added and not removed in the current
// location.
func (hg *HypergraphCRDT) LookupVertex(v *Vertex) bool {
	location := v.GetLocation()
	return hg.vertexAdds[location].Has(v) && !hg.vertexRemoves[location].Has(v)
}

// LookupHyperedge checks if a hyperedge and its extrinsics can be looked up.
func (hg *HypergraphCRDT) LookupHyperedge(h *Hyperedge) bool {
	return hg.LookupAtomSet(h.extrinsics) &&
		hg.hyperedgeAdds[h.GetLocation()].Has(h) &&
		!hg.hyperedgeRemoves[h.GetLocation()].Has(h)
}

// Within checks if atom `a` is within hyperedge `h` directly or transitively.
func (hg *HypergraphCRDT) Within(a, h Atom) bool {
	switch ha := h.(type) {
	case *Hyperedge:
		_, ok := ha.extrinsics[a.GetID()]
		if ok || a.GetID() == h.GetID() {
			return true
		}
		for _, extrinsic := range ha.extrinsics {
			if he, ok := extrinsic.(*Hyperedge); ok {
				for _, hyperExtrinsic := range he.extrinsics {
					if hyperHe, ok := hyperExtrinsic.(*Hyperedge); ok {
						if hg.LookupHyperedge(hyperHe) {
							if _, ok := hyperHe.extrinsics[a.GetID()]; ok &&
								hg.Within(hyperHe, h) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// GetReconciledVertexSet computes the set of vertices that have been added but
// not removed for a location.
func (hg *HypergraphCRDT) GetReconciledVertexSet(l Location) *IdSet {
	vertices := NewIdSet("vertex")
	for _, v := range hg.vertexAdds[l].atoms {
		if !hg.vertexRemoves[l].Has(v) {
			vertices.Add(v)
		}
	}
	return vertices
}

// GetReconciledHyperedgeSet computes the set of hyperedges that have been added
// but not removed for a location.
func (hg *HypergraphCRDT) GetReconciledHyperedgeSet(l Location) *IdSet {
	hyperedges := NewIdSet("hyperedge")
	for _, h := range hg.hyperedgeAdds[l].atoms {
		if !hg.hyperedgeRemoves[l].Has(h) {
			hyperedges.Add(h)
		}
	}
	return hyperedges
}
