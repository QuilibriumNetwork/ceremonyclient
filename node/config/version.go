package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2024, time.March, 15, 4, 20, 0, 0, time.UTC)
}

func GetMinimumVersion() []byte {
	return []byte{0x01, 0x04, 0x08}
}

func GetVersion() []byte {
	return []byte{0x01, 0x04, 0x08}
}

func GetVersionString() string {
	return fmt.Sprintf("%d.%d.%d", GetVersion()[0], GetVersion()[1], GetVersion()[2])
}
