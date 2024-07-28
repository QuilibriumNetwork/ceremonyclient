package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2024, time.May, 8, 5, 0, 0, 0, time.UTC)
}

func GetMinimumVersion() []byte {
	return []byte{0x01, 0x04, 0x13}
}

func GetVersion() []byte {
	return []byte{0x01, 0x04, 0x15}
}

func GetVersionString() string {
	return FormatVersion(GetVersion())
}

func FormatVersion(version []byte) string {
	if len(version) == 3 {
		return fmt.Sprintf(
			"%d.%d.%d",
			version[0], version[1], version[2],
		)
	} else {
		return fmt.Sprintf(
			"%d.%d.%d-p%d",
			version[0], version[1], version[2], version[3],
		)
	}
}

func GetPatchNumber() byte {
	return 0x01
}
