package cluster

import "testing"

func TestDistributedPolicyNeverImpliesSharedRecords(t *testing.T) {
	for _, name := range []string{"records.data", "files.data", "auth.sessions", "raw.database"} {
		policy, ok := PolicyFor(name)
		if !ok || !policy.NodeLocalOnly {
			t.Fatalf("%s must be explicitly node-local", name)
		}
		if policy.FanOutRead || policy.PropagatableLater {
			t.Fatalf("%s must not be fanned out or propagated", name)
		}
	}
}

func TestPropagatableObjectsRemainExplicitAndDeferred(t *testing.T) {
	for _, name := range []string{"schema.definition", "roles.policy"} {
		policy, ok := PolicyFor(name)
		if !ok || !policy.PropagatableLater || !policy.AuthoritativeOwner {
			t.Fatalf("%s propagation policy is incomplete", name)
		}
	}
}
