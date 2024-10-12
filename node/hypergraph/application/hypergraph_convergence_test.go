package application_test

import (
	"math/rand"
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
)

type Operation struct {
	Type      string // "AddVertex", "RemoveVertex", "AddHyperedge", "RemoveHyperedge"
	Vertex    *application.Vertex
	Hyperedge *application.Hyperedge
}

func TestConvergence(t *testing.T) {
	numParties := 3
	numOperations := 100

	// Generate a set of vertices and hyperedges
	vertices := make([]*application.Vertex, numOperations)
	for i := 0; i < numOperations; i++ {
		vertices[i] = &application.Vertex{
			AppAddress:   [32]byte{byte(i % 256)},
			DataAddress:  [32]byte{byte(i / 256)},
			SegmentOrder: uint16(i),
		}
	}

	hyperedges := make([]*application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = &application.Hyperedge{
			AppAddress:  [32]byte{byte(i % 256)},
			DataAddress: [32]byte{byte(i / 256)},
			Extrinsics:  make(map[[66]byte]application.Atom),
		}
		// Add some random vertices as extrinsics
		for j := 0; j < 3; j++ {
			v := vertices[rand.Intn(len(vertices))]
			hyperedges[i].Extrinsics[v.GetID()] = v
		}
	}

	// Generate a sequence of operations
	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[rand.Intn(len(vertices))]}
		case 1:
			operations1[i] = Operation{Type: "RemoveVertex", Vertex: vertices[rand.Intn(len(vertices))]}
		}
	}
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations2[i] = Operation{Type: "AddHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		case 1:
			operations2[i] = Operation{Type: "RemoveHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		}
	}

	// Create CRDTs for each party
	crdts := make([]*application.Hypergraph, numParties)
	for i := 0; i < numParties; i++ {
		crdts[i] = application.NewHypergraph()
	}

	// Apply operations in different orders for each party
	for i := 0; i < numParties; i++ {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(operations1), func(i, j int) { operations1[i], operations1[j] = operations1[j], operations1[i] })
		rand.Shuffle(len(operations2), func(i, j int) { operations2[i], operations2[j] = operations2[j], operations2[i] })

		for _, op := range operations1 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(op.Hyperedge)
			}
		}
		for _, op := range operations2 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(op.Hyperedge)
			}
		}
	}

	// Verify that all CRDTs have converged to the same state
	// Additional verification: check specific vertices and hyperedges
	for _, v := range vertices {
		state := crdts[0].LookupVertex(v)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupVertex(v) != state {
				t.Errorf("Vertex %v has different state in CRDT %d", v, i)
			}
		}
	}

	for _, h := range hyperedges {
		state := crdts[0].LookupHyperedge(h)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupHyperedge(h) != state {
				t.Errorf("Hyperedge %v has different state in CRDT %d", h, i)
			}
		}
	}
}
