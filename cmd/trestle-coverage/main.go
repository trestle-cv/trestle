package main

import (
	"fmt"
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/trestle-cv/trestle/internal/operations"
	"os"
	"path/filepath"
)

func main() {
	root := "."
	if len(os.Args) == 2 {
		root = os.Args[1]
	} else if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: trestle-coverage [repository-root]")
		os.Exit(2)
	}
	if err := contracttest.WriteMatrixArtifacts(filepath.Join(root, "docs/generated/functional-coverage.json"), filepath.Join(root, "docs/generated/functional-coverage.md"), operations.Manifest()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
