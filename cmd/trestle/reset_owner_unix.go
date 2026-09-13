//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func preserveResetDirectoryOwner(path string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine prior data-directory ownership")
	}
	if err := os.Chown(path, int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("restore data-directory ownership: %w", err)
	}
	return nil
}
