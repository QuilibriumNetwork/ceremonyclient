package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2024, time.April, 4, 6, 20, 0, 0, time.UTC)
}

func GetMinimumVersion() []byte {
	return []byte{0x01, 0x04, 0x10}
}

func GetVersion() []byte {
	return []byte{0x01, 0x04, 0x11}
}

func GetVersionString() string {
	return FormatVersion(GetVersion())
}

func FormatVersion(version []byte) string {
	return fmt.Sprintf(
		"%d.%d.%d",
		version[0], version[1], version[2],
	)
}
