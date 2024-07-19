package inmem

func InShard(a Atom, l Location) bool {
	return a.GetLocation() == l
}

type ShardSet struct {
	VertexSet    *IdSet
	HyperedgeSet *IdSet
}

func ShardAtom(a Atom) map[Location]*ShardSet {
	switch atom := a.(type) {
	case *Vertex:
		return ShardVertex(atom)
	case *Hyperedge:
		return ShardHyperedge(atom)
	default:
		return nil
	}
}

func ShardAtomSet(atomSet map[string]Atom) map[Location]*ShardSet {
	result := make(map[Location]*ShardSet)
	for _, a := range atomSet {
		result[a.GetLocation()] = &ShardSet{
			VertexSet:    NewIdSet("vertex"),
			HyperedgeSet: NewIdSet("hyperedge"),
		}
	}

	for _, atom := range atomSet {
		shard := ShardAtom(atom)
		for location, locationShard := range shard {
			for _, locationAtom := range locationShard.VertexSet.atoms {
				if _, ok := result[location]; !ok {
					result[location] = &ShardSet{
						VertexSet:    NewIdSet("vertex"),
						HyperedgeSet: NewIdSet("hyperedge"),
					}
				}
				result[location].VertexSet.Add(locationAtom)
			}
			for _, locationAtom := range locationShard.HyperedgeSet.atoms {
				if _, ok := result[location]; !ok {
					result[location] = &ShardSet{
						VertexSet:    NewIdSet("vertex"),
						HyperedgeSet: NewIdSet("hyperedge"),
					}
				}
				result[location].HyperedgeSet.Add(locationAtom)
			}
		}
	}
	return result
}

func ShardVertex(v *Vertex) map[Location]*ShardSet {
	result := make(map[Location]*ShardSet)
	if _, ok := result[v.location]; !ok {
		result[v.location] = &ShardSet{
			VertexSet:    NewIdSet("vertex"),
			HyperedgeSet: NewIdSet("hyperedge"),
		}
	}
	result[v.location].VertexSet.Add(v)
	return result
}

// ShardHyperedge shards a hyperedge and its extrinsics across locations.
func ShardHyperedge(h *Hyperedge) map[Location]*ShardSet {
	extrinsicShardSet := ShardAtomSet(h.extrinsics)
	result := make(map[Location]*ShardSet)

	for l, s := range extrinsicShardSet {
		result[l] = s
	}

	if _, ok := result[h.location]; !ok {
		result[h.location] = &ShardSet{
			VertexSet:    NewIdSet("vertex"),
			HyperedgeSet: NewIdSet("hyperedge"),
		}
	}

	result[h.location].HyperedgeSet.Add(h)

	return result
}
