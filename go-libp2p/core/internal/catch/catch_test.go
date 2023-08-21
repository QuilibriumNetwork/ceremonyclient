package catch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatch(t *testing.T) {
	buf := new(bytes.Buffer)

	oldPanicWriter := panicWriter
	t.Cleanup(func() { panicWriter = oldPanicWriter })
	panicWriter = buf

	panicAndCatch := func() (err error) {
		defer func() { HandlePanic(recover(), &err, "somewhere") }()

		panic("here")
	}

	err := panicAndCatch()
	require.Error(t, err)
	require.Contains(t, err.Error(), "panic in somewhere: here")

	require.Contains(t, buf.String(), "caught panic: here")
}
