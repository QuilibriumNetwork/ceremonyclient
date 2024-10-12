package application_test

import (
	"bytes"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
)

func TestHypergraph(t *testing.T) {
	hg := application.NewHypergraph()

	// Test vertex operations
	t.Run("Vertex Operations", func(t *testing.T) {
		v1 := &application.Vertex{AppAddress: [32]byte{1}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		v2 := &application.Vertex{AppAddress: [32]byte{1}, DataAddress: [32]byte{2}, SegmentOrder: 1}

		// Add vertices
		err := hg.AddVertex(v1)
		if err != nil {
			t.Errorf("Failed to add vertex v1: %v", err)
		}
		err = hg.AddVertex(v2)
		if err != nil {
			t.Errorf("Failed to add vertex v2: %v", err)
		}

		// Lookup vertices
		if !hg.LookupVertex(v1) {
			t.Error("Failed to lookup vertex v1")
		}
		if !hg.LookupVertex(v2) {
			t.Error("Failed to lookup vertex v2")
		}

		// Remove vertex
		err = hg.RemoveVertex(v1)
		if err != nil {
			t.Errorf("Failed to remove vertex v1: %v", err)
		}
		if hg.LookupVertex(v1) {
			t.Error("Vertex v1 still exists after removal")
		}
		if !hg.LookupVertex(v2) {
			t.Error("Vertex v2 was incorrectly removed")
		}
	})

	// Test hyperedge operations
	t.Run("Hyperedge Operations", func(t *testing.T) {
		v3 := &application.Vertex{AppAddress: [32]byte{2}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		v4 := &application.Vertex{AppAddress: [32]byte{2}, DataAddress: [32]byte{2}, SegmentOrder: 1}
		hg.AddVertex(v3)
		hg.AddVertex(v4)

		h1 := &application.Hyperedge{
			AppAddress:  [32]byte{3},
			DataAddress: [32]byte{1},
			Extrinsics:  map[[66]byte]application.Atom{v3.GetID(): v3, v4.GetID(): v4},
		}

		// Add hyperedge
		err := hg.AddHyperedge(h1)
		if err != nil {
			t.Errorf("Failed to add hyperedge h1: %v", err)
		}

		// Lookup hyperedge
		if !hg.LookupHyperedge(h1) {
			t.Error("Failed to lookup hyperedge h1")
		}

		// Remove hyperedge
		err = hg.RemoveHyperedge(h1)
		if err != nil {
			t.Errorf("Failed to remove hyperedge h1: %v", err)
		}
		if hg.LookupHyperedge(h1) {
			t.Error("Hyperedge h1 still exists after removal")
		}
	})

	// Test "within" relationship
	t.Run("Within Relationship", func(t *testing.T) {
		v5 := &application.Vertex{AppAddress: [32]byte{4}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		v6 := &application.Vertex{AppAddress: [32]byte{4}, DataAddress: [32]byte{2}, SegmentOrder: 1}
		hg.AddVertex(v5)
		hg.AddVertex(v6)

		h2 := &application.Hyperedge{
			AppAddress:  [32]byte{5},
			DataAddress: [32]byte{1},
			Extrinsics:  map[[66]byte]application.Atom{v5.GetID(): v5, v6.GetID(): v6},
		}
		hg.AddHyperedge(h2)

		if !hg.Within(v5, h2) {
			t.Error("v5 should be within h2")
		}
		if !hg.Within(v6, h2) {
			t.Error("v6 should be within h2")
		}

		v7 := &application.Vertex{AppAddress: [32]byte{4}, DataAddress: [32]byte{3}, SegmentOrder: 1}
		hg.AddVertex(v7)
		if hg.Within(v7, h2) {
			t.Error("v7 should not be within h2")
		}
	})

	// Test nested hyperedges
	t.Run("Nested Hyperedges", func(t *testing.T) {
		v8 := &application.Vertex{AppAddress: [32]byte{6}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		v9 := &application.Vertex{AppAddress: [32]byte{6}, DataAddress: [32]byte{2}, SegmentOrder: 1}
		hg.AddVertex(v8)
		hg.AddVertex(v9)

		h3 := &application.Hyperedge{
			AppAddress:  [32]byte{7},
			DataAddress: [32]byte{1},
			Extrinsics:  map[[66]byte]application.Atom{v8.GetID(): v8},
		}
		h4 := &application.Hyperedge{
			AppAddress:  [32]byte{7},
			DataAddress: [32]byte{2},
			Extrinsics:  map[[66]byte]application.Atom{h3.GetID(): h3, v9.GetID(): v9},
		}
		hg.AddHyperedge(h3)
		hg.AddHyperedge(h4)

		if !hg.Within(v8, h4) {
			t.Error("v8 should be within h4 (nested)")
		}
		if !hg.Within(v9, h4) {
			t.Error("v9 should be within h4 (direct)")
		}
	})

	// Test error cases
	t.Run("Error Cases", func(t *testing.T) {
		v10 := &application.Vertex{AppAddress: [32]byte{8}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		h5 := &application.Hyperedge{
			AppAddress:  [32]byte{8},
			DataAddress: [32]byte{2},
			Extrinsics:  map[[66]byte]application.Atom{v10.GetID(): v10},
		}

		// Try to add hyperedge with non-existent vertex
		err := hg.AddHyperedge(h5)
		if err != application.ErrMissingExtrinsics {
			t.Errorf("Expected ErrMissingExtrinsics, got %v", err)
		}

		// Add vertex and hyperedge
		hg.AddVertex(v10)
		hg.AddHyperedge(h5)

		// Try to remove vertex that is an extrinsic
		err = hg.RemoveVertex(v10)
		if err != application.ErrIsExtrinsic {
			t.Errorf("Expected ErrIsExtrinsic, got %v", err)
		}
	})

	// Test sharding
	t.Run("Sharding", func(t *testing.T) {
		v11 := &application.Vertex{AppAddress: [32]byte{9}, DataAddress: [32]byte{1}, SegmentOrder: 1}
		v12 := &application.Vertex{AppAddress: [32]byte{9}, DataAddress: [32]byte{2}, SegmentOrder: 1}
		hg.AddVertex(v11)
		hg.AddVertex(v12)

		shard11 := application.GetShardAddress(v11)
		shard12 := application.GetShardAddress(v12)

		if !bytes.Equal(shard11.L1[:], shard12.L1[:]) ||
			bytes.Equal(shard11.L2[:], shard12.L2[:]) {
			t.Error("v11 and v12 should be in the same L1 shard and not the same L2 shard")
		}
	})
}
