package inmem_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/inmem"
)

func TestIdSet(t *testing.T) {
	v := hypergraph.NewVertex("1", "here")
	h := hypergraph.NewHyperedge("2", "here", make(map[string]hypergraph.Atom))

	vset := hypergraph.NewIdSet("vertex")
	hset := hypergraph.NewIdSet("hyperedge")
	assert.NoError(t, vset.Add(v))
	assert.NoError(t, hset.Add(h))

	assert.True(t, vset.Has(v))
	assert.True(t, hset.Has(h))

	vset.Delete(v)
	assert.False(t, hset.Has(v))
}

func TestCRDT(t *testing.T) {
	loc1 := hypergraph.Location("here1")
	loc2 := hypergraph.Location("here2")
	hg := hypergraph.NewHypergraphCRDT([]hypergraph.Location{loc1, loc2})

	v1 := hypergraph.NewVertex("1", loc1)
	v2 := hypergraph.NewVertex("2", loc2)
	h1 := hypergraph.NewHyperedge("h1", loc1, make(map[string]hypergraph.Atom))

	hg.AddVertex(v1)
	hg.AddVertex(v2)
	hg.AddHyperedge(h1)
	h2vs := map[string]hypergraph.Atom{}
	h2vs["1"] = v1
	h2vs["2"] = v2
	h2 := hypergraph.NewHyperedge("h2", loc2, h2vs)
	hg.AddHyperedge(h2)

	h3vs := map[string]hypergraph.Atom{}
	h3vs["h2"] = h2
	h3 := hypergraph.NewHyperedge("h3", loc1, h3vs)
	hg.AddHyperedge(h3)

	assert.NotNil(t, hg.LookupVertex(v1))
	assert.NotNil(t, hg.LookupVertex(v2))
	assert.NotNil(t, hg.LookupHyperedge(h1))
	assert.NotNil(t, hg.LookupHyperedge(h2))
	assert.NotNil(t, hg.LookupHyperedge(h3))

	assert.True(t, hg.GetReconciledVertexSet(v1.GetLocation()).Has(v1))
	assert.False(t, hg.GetReconciledVertexSet(v1.GetLocation()).Has(v2))
	assert.True(t, hg.GetReconciledVertexSet(v2.GetLocation()).Has(v2))
	assert.True(t, hg.GetReconciledHyperedgeSet(v1.GetLocation()).Has(h1))
	assert.False(t, hg.GetReconciledHyperedgeSet(h1.GetLocation()).Has(h2))
	assert.True(t, hg.GetReconciledHyperedgeSet(h2.GetLocation()).Has(h2))
	assert.True(t, hg.GetReconciledHyperedgeSet(h3.GetLocation()).Has(h3))

	assert.Error(t, hg.RemoveHyperedge(h2))
	assert.True(t, hg.GetReconciledHyperedgeSet(h2.GetLocation()).Has(h2))
	assert.NoError(t, hg.RemoveHyperedge(h3))
	assert.False(t, hg.GetReconciledHyperedgeSet(h3.GetLocation()).Has(h3))
	assert.Error(t, hg.RemoveVertex(v1))
	assert.True(t, hg.GetReconciledVertexSet(v1.GetLocation()).Has(v1))
	assert.NoError(t, hg.RemoveHyperedge(h2))
	assert.False(t, hg.GetReconciledHyperedgeSet(h2.GetLocation()).Has(h2))
	assert.NoError(t, hg.RemoveVertex(v1))
	assert.False(t, hg.GetReconciledVertexSet(v1.GetLocation()).Has(v1))
	assert.NoError(t, hg.RemoveVertex(v2))
	assert.False(t, hg.GetReconciledVertexSet(v2.GetLocation()).Has(v2))
}
