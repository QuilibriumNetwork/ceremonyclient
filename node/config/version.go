package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2024, time.March, 10, 5, 30, 0, 0, time.UTC)
}

func GetMinimumVersion() []byte {
	return []byte{0x01, 0x04, 0x05}
}

func GetVersion() []byte {
	return []byte{0x01, 0x04, 0x07}
}

func GetVersionString() string {
	return fmt.Sprintf("%d.%d.%d", GetVersion()[0], GetVersion()[1], GetVersion()[2])
}
