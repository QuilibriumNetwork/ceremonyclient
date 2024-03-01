//go:build !windows
// +build !windows

package utils

import "golang.org/x/sys/unix"

func GetDiskSpace(dir string) uint64 {
	var stat unix.Statfs_t

	err := unix.Statfs(dir, &stat)
	if err != nil {
		panic(err)
	}

	return stat.Bavail * uint64(stat.Bsize)
}
