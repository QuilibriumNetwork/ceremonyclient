package multiaddr

import "fmt"

// Split returns the sub-address portions of a multiaddr.
func Split(m Multiaddr) []Multiaddr {
	if _, ok := m.(*Component); ok {
		return []Multiaddr{m}
	}
	var addrs []Multiaddr
	var err error
	ForEach(m, func(c Component, e error) bool {
		if e != nil {
			err = e
			return false
		}
		addrs = append(addrs, &c)
		return true
	})

	if err != nil {
		return []Multiaddr{}
	}

	return addrs
}

// Join returns a combination of addresses.
func Join(ms ...Multiaddr) Multiaddr {
	switch len(ms) {
	case 0:
		// empty multiaddr, unfortunately, we have callers that rely on
		// this contract.
		return &multiaddr{}
	case 1:
		return ms[0]
	}

	length := 0
	for _, m := range ms {
		if m == nil {
			continue
		}
		length += len(m.Bytes())
	}

	bidx := 0
	b := make([]byte, length)
	if length == 0 {
		return nil
	}
	for _, mb := range ms {
		if mb == nil {
			continue
		}
		bidx += copy(b[bidx:], mb.Bytes())
	}
	if length == 0 {
		return nil
	}
	return &multiaddr{bytes: b}
}

// Cast re-casts a byte slice as a multiaddr.
func Cast(b []byte) (Multiaddr, error) {
	m, err := NewMultiaddrBytes(b)
	if err != nil {
		return nil, fmt.Errorf("multiaddr failed to parse: %s", err)
	}
	return m, nil
}

// StringCast like Cast, but parses a string.
func StringCast(s string) (Multiaddr, error) {
	m, err := NewMultiaddr(s)
	if err != nil {
		return nil, fmt.Errorf("multiaddr failed to parse: %s", err)
	}
	return m, nil
}

// SplitFirst returns the first component and the rest of the multiaddr.
func SplitFirst(m Multiaddr) (*Component, Multiaddr, error) {
	if m == nil {
		return nil, nil, nil
	}
	// Shortcut if we already have a component
	if c, ok := m.(*Component); ok {
		return c, nil, nil
	}

	b := m.Bytes()
	if len(b) == 0 {
		return nil, nil, nil
	}
	n, c, err := readComponent(b)
	if err != nil {
		return nil, nil, err
	}
	if len(b) == n {
		return &c, nil, nil
	}
	return &c, &multiaddr{b[n:]}, nil
}

// SplitLast returns the rest of the multiaddr and the last component.
func SplitLast(m Multiaddr) (Multiaddr, *Component, error) {
	if m == nil {
		return nil, nil, nil
	}

	// Shortcut if we already have a component
	if c, ok := m.(*Component); ok {
		return nil, c, nil
	}

	b := m.Bytes()
	if len(b) == 0 {
		return nil, nil, nil
	}

	var (
		c      Component
		err    error
		offset int
	)
	for {
		var n int
		n, c, err = readComponent(b[offset:])
		if err != nil {
			return nil, nil, err
		}
		if len(b) == n+offset {
			// Reached end
			if offset == 0 {
				// Only one component
				return nil, &c, nil
			}
			return &multiaddr{b[:offset]}, &c, nil
		}
		offset += n
	}
}

// SplitFunc splits the multiaddr when the callback first returns true. The
// component on which the callback first returns will be included in the
// *second* multiaddr.
func SplitFunc(m Multiaddr, cb func(Component) bool) (Multiaddr, Multiaddr, error) {
	if m == nil {
		return nil, nil, nil
	}
	// Shortcut if we already have a component
	if c, ok := m.(*Component); ok {
		if cb(*c) {
			return nil, m, nil
		}
		return m, nil, nil
	}
	b := m.Bytes()
	if len(b) == 0 {
		return nil, nil, nil
	}
	var (
		c      Component
		err    error
		offset int
	)
	for offset < len(b) {
		var n int
		n, c, err = readComponent(b[offset:])
		if err != nil {
			return nil, nil, err
		}
		if cb(c) {
			break
		}
		offset += n
	}
	switch offset {
	case 0:
		return nil, m, nil
	case len(b):
		return m, nil, nil
	default:
		return &multiaddr{b[:offset]}, &multiaddr{b[offset:]}, nil
	}
}

// ForEach walks over the multiaddr, component by component.
//
// This function iterates over components *by value* to avoid allocating.
// Return true to continue iteration, false to stop.
func ForEach(m Multiaddr, cb func(c Component, err error) bool) {
	if m == nil {
		return
	}
	// Shortcut if we already have a component
	if c, ok := m.(*Component); ok {
		cb(*c, nil)
		return
	}

	b := m.Bytes()
	for len(b) > 0 {
		n, c, err := readComponent(b)
		if !cb(c, err) {
			return
		}
		b = b[n:]
	}
}
