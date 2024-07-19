package inmem

import "errors"

type AtomType string
type Location string

var ErrInvalidAtomType error = errors.New("invalid atom type for set")

type Vertex struct {
	id       string
	location Location
}

type Hyperedge struct {
	id         string
	location   Location
	extrinsics map[string]Atom
}

type Atom interface {
	GetID() string
	GetAtomType() AtomType
	GetLocation() Location
}

var _v Atom = (*Vertex)(nil)
var _h Atom = (*Hyperedge)(nil)

func NewVertex(id string, location Location) *Vertex {
	return &Vertex{
		id,
		location,
	}
}

func NewHyperedge(
	id string,
	location Location,
	extrinsics map[string]Atom,
) *Hyperedge {
	return &Hyperedge{
		id,
		location,
		extrinsics,
	}
}

func (v *Vertex) GetID() string {
	return v.id
}

func (h *Hyperedge) GetID() string {
	return h.id
}

func (v *Vertex) GetAtomType() AtomType {
	return "vertex"
}

func (h *Hyperedge) GetAtomType() AtomType {
	return "hyperedge"
}

func (v *Vertex) GetLocation() Location {
	return v.location
}

func (h *Hyperedge) GetLocation() Location {
	return h.location
}

type IdSet struct {
	atomType AtomType
	atoms    map[string]Atom
}

func NewIdSet(atomType AtomType) *IdSet {
	return &IdSet{atomType: atomType, atoms: make(map[string]Atom)}
}

// Add adds an atom to the IdSet if it's not already present.
func (set *IdSet) Add(atom Atom) error {
	switch a := atom.(type) {
	case *Vertex:
		if set.atomType != "vertex" {
			return ErrInvalidAtomType
		}
		if _, exists := set.atoms[a.GetID()]; !exists {
			set.atoms[a.GetID()] = a
		}
	case *Hyperedge:
		if set.atomType != "hyperedge" {
			return ErrInvalidAtomType
		}
		if _, exists := set.atoms[a.GetID()]; !exists {
			set.atoms[a.GetID()] = a
		}
	}

	return nil
}

// Delete removes an atom from the IdSet and returns true if the atom was
// present.
func (set *IdSet) Delete(atom Atom) bool {
	switch a := atom.(type) {
	case *Vertex:
		if _, exists := set.atoms[a.GetID()]; exists {
			delete(set.atoms, a.GetID())
			return true
		}
	case *Hyperedge:
		if _, exists := set.atoms[a.GetID()]; exists {
			delete(set.atoms, a.GetID())
			return true
		}
	}
	return false
}

// Has checks if an atom is in the IdSet.
func (set *IdSet) Has(atom Atom) bool {
	switch a := atom.(type) {
	case *Vertex:
		_, exists := set.atoms[a.GetID()]
		return exists
	case *Hyperedge:
		_, exists := set.atoms[a.GetID()]
		return exists
	}
	return false
}
