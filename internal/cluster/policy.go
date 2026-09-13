package cluster

// OperationPolicy is deliberately product-local. Gantry Core provides routing
// mechanics; Trestle decides what may be queried, targeted, propagated later,
// or must remain strictly node-local.
type OperationPolicy struct {
	Operation          string `json:"operation"`
	FanOutRead         bool   `json:"fan_out_read"`
	TargetedRemote     bool   `json:"targeted_remote"`
	PropagatableLater  bool   `json:"propagatable_later"`
	AuthoritativeOwner bool   `json:"authoritative_owner"`
	NodeLocalOnly      bool   `json:"node_local_only"`
}

var Policies = []OperationPolicy{
	{Operation: "cluster.health", FanOutRead: true, TargetedRemote: true},
	{Operation: "cluster.schema.compare", FanOutRead: true, TargetedRemote: true},
	{Operation: "jobs.status", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "webhooks.status", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "functions.status", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "backups.status", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "schema.definition", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "roles.policy", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "records.data", AuthoritativeOwner: true, NodeLocalOnly: true},
	{Operation: "files.data", AuthoritativeOwner: true, NodeLocalOnly: true},
	{Operation: "auth.sessions", AuthoritativeOwner: true, NodeLocalOnly: true},
	{Operation: "raw.database", NodeLocalOnly: true},
}

func PolicyFor(operation string) (OperationPolicy, bool) {
	for _, policy := range Policies {
		if policy.Operation == operation {
			return policy, true
		}
	}
	return OperationPolicy{}, false
}
