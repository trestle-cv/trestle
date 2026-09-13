package propagation

import (
	"encoding/json"
	core "github.com/gantry-tools/gantry-core/propagation"
	"testing"
)

func TestTrestleKinds(t *testing.T) {
	e := core.Envelope{Kind: "schema", ID: "users", SchemaVersion: 1, Revision: 1, SourceNode: "n", Target: "all", Conflict: core.ConflictReject, Actor: core.Actor{Permission: "collections.update"}, Payload: json.RawMessage(`{"fields":[]}`)}
	if err := ValidateEnvelope(e); err != nil {
		t.Fatal(err)
	}
	e.Kind = "record"
	if err := ValidateEnvelope(e); err == nil {
		t.Fatal("records must remain node-local")
	}
}
