package propagation

import (
	"fmt"
	core "github.com/gantry-tools/gantry-core/propagation"
)

type KindPolicy struct {
	Kind       string
	Reversible bool
	Mergeable  bool
	Permission string
}

var policies = map[string]KindPolicy{
	"project-setting":     {Kind: "project-setting", Reversible: true, Permission: "settings.update"},
	"schema":              {Kind: "schema", Reversible: true, Permission: "collections.update"},
	"access-policy":       {Kind: "access-policy", Reversible: true, Permission: "roles.update"},
	"job-definition":      {Kind: "job-definition", Reversible: true, Permission: "jobs.update"},
	"webhook-definition":  {Kind: "webhook-definition", Reversible: true, Permission: "webhooks.update"},
	"function-definition": {Kind: "function-definition", Reversible: true, Permission: "functions.update"},
}

func Policy(kind string) (KindPolicy, bool) { p, ok := policies[kind]; return p, ok }
func ValidateEnvelope(e core.Envelope) error {
	p, ok := Policy(e.Kind)
	if !ok {
		return fmt.Errorf("trestle propagation kind %q is not supported", e.Kind)
	}
	if e.Actor.Permission != "" && e.Actor.Permission != p.Permission {
		return fmt.Errorf("permission %q does not match %q", e.Actor.Permission, p.Permission)
	}
	return e.Validate()
}
func Kinds() []string {
	return []string{"access-policy", "function-definition", "job-definition", "project-setting", "schema", "webhook-definition"}
}
