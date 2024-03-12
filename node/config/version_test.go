package config

import (
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
	"time"
)

func TestGetMinimumVersion(t *testing.T) {
	minVersion := GetMinimumVersion()

	assert.Equal(t, 3, len(minVersion), "Expected version to have exactly 3 bytes; got %v", len(minVersion))

	version := GetVersion()

	assert.GreaterOrEqual(t, version[0], minVersion[0])

	if minVersion[0] == version[0] {
		assert.GreaterOrEqual(t, version[1], minVersion[1])

		if minVersion[1] == version[1] {
			assert.GreaterOrEqual(t, version[2], minVersion[2])
		}
	}
}

func TestGetVersion(t *testing.T) {
	version := GetVersion()

	assert.Equal(t, 3, len(version), "Expected version to have exactly 3 bytes; got %v", len(version))
}

func TestGetMinimumVersionCutoff(t *testing.T) {
	cutoff := GetMinimumVersionCutoff()

	assert.True(t, cutoff.Before(time.Now()))
	assert.True(t, cutoff.After(time.Date(2024, time.March, 1, 0, 0, 0, 0, time.UTC)))
}

func TestGetVersionString(t *testing.T) {
	version := GetVersionString()

	versionRegexp := regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+")

	assert.Regexp(t, versionRegexp, version)
}
