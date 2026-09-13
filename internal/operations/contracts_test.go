package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOperationContracts(t *testing.T) {
	if err := contracttest.Require(Manifest()); err != nil {
		t.Fatal(err)
	}
	if f := contracttest.CertificationFindings(Manifest()); len(f) != 0 {
		t.Fatalf("certification findings: %+v", f)
	}
}
func TestGeneratedCoverageIsCurrent(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	if err := contracttest.CheckMatrixArtifacts(filepath.Join(root, "docs/generated/functional-coverage.json"), filepath.Join(root, "docs/generated/functional-coverage.md"), Manifest()); err != nil {
		t.Fatal(err)
	}
}
