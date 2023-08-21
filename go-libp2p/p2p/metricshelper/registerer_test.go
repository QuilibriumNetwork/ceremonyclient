package metricshelper

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/stretchr/testify/require"
)

func TestRegisterCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	c1 := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "counter",
		},
	)
	c2 := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "test",
			Name:      "gauge",
		},
	)
	// c3 == c1
	c3 := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "counter",
		},
	)
	require.NotPanics(t, func() { RegisterCollectors(reg, c1, c2) })
	require.NotPanics(t, func() { RegisterCollectors(reg, c3) }, "should not panic on duplicate registration")
}
