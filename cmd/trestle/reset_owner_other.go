//go:build !unix

package main

import "io/fs"

func preserveResetDirectoryOwner(_ string, _ fs.FileInfo) error { return nil }
