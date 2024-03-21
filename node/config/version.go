package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2024, time.March, 21, 5, 00, 0, 0, time.UTC)
}

func GetMinimumVersion() []byte {
	return []byte{0x01, 0x04, 0x0B}
}

func GetVersion() []byte {
	return []byte{0x01, 0x04, 0x0B}
}

func GetVersionString() string {
	return fmt.Sprintf(
		"%d.%d.%d",
		GetVersion()[0], GetVersion()[1], GetVersion()[2],
	)
}
