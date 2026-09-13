// Package operations declares Trestle's canonical functional operation surface.
package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/gantry-tools/gantry-core/operation"
	"strings"
)

type spec struct {
	id, method, path, resource, verb, test string
	kind                                   operation.Kind
	boundary                               operation.Boundary
	capability                             string
	automation                             operation.Automation
	website                                bool
	secrets                                []string
}

func sp(id, method, path, resource, verb string, kind operation.Kind, boundary operation.Boundary, test string) spec {
	return spec{id: id, method: method, path: path, resource: resource, verb: verb, kind: kind, boundary: boundary, test: test, automation: operation.Automatable, website: true}
}

var specs = []spec{
	sp("trestle.system.health", "GET", "/system/health", "system", "health", operation.Read, operation.Public, "internal/server/server_test.go"),
	sp("trestle.system.ready", "GET", "/system/ready", "system", "ready", operation.Read, operation.Public, "internal/server/server_test.go"),
	sp("trestle.system.version", "GET", "/system/version", "system", "version", operation.Read, operation.Public, "internal/server/server_test.go"),
	sp("trestle.launcher.instances.list", "GET", "/api/launcher/instances", "launcher-instances", "list", operation.Read, operation.Public, "internal/launcher/handler_test.go"),
	sp("trestle.launcher.config.update", "PUT", "/api/launcher/config", "launcher-config", "update", operation.Mutation, operation.Capability, "internal/launcher/handler_test.go"),
	sp("trestle.admin.setup.status", "GET", "/admin/v1/setup/status", "setup", "status", operation.Read, operation.Public, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.setup.apply", "POST", "/admin/v1/setup", "setup", "apply", operation.Mutation, operation.Public, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.session.login", "POST", "/admin/v1/session", "auth", "login", operation.Mutation, operation.Public, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.session.current", "GET", "/admin/v1/session", "auth", "session", operation.Read, operation.Session, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.session.logout", "DELETE", "/admin/v1/session", "auth", "logout", operation.Destructive, operation.Session, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.password.update", "POST", "/admin/v1/password", "auth-password", "update", operation.Mutation, operation.Session, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.users.list", "GET", "/admin/v1/manage/users", "users", "list", operation.Read, operation.Capability, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.users.manage", "POST", "/admin/v1/manage/users", "users", "manage", operation.Destructive, operation.Capability, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.roles.list", "GET", "/admin/v1/manage/roles", "roles", "list", operation.Read, operation.Capability, "internal/adminauth/handler_test.go"),
	sp("trestle.admin.roles.update", "PUT", "/admin/v1/manage/roles", "roles", "update", operation.Mutation, operation.Capability, "internal/adminauth/handler_test.go"),
	sp("trestle.database.setup.read", "GET", "/admin/v1/database/setup", "database", "setup-status", operation.Read, operation.Public, "internal/databasesetup/handler_test.go"),
	sp("trestle.database.setup.apply", "POST", "/admin/v1/database/setup", "database", "setup", operation.Mutation, operation.Public, "internal/databasesetup/handler_test.go"),
	sp("trestle.appauth.capability", "GET", "/api/v1/auth/capability", "app-auth", "capability", operation.Read, operation.Public, "internal/appauth/handler_test.go"),
	sp("trestle.appauth.register", "POST", "/api/v1/auth/register", "app-auth", "register", operation.Mutation, operation.Public, "internal/appauth/registration_test.go"),
	sp("trestle.appauth.invite.accept", "POST", "/api/v1/auth/invite/accept", "app-auth", "accept-invite", operation.Mutation, operation.Public, "internal/appauth/registration_test.go"),
	sp("trestle.appauth.access.request", "POST", "/api/v1/auth/access-request", "app-auth", "request-access", operation.Mutation, operation.Public, "internal/appauth/registration_test.go"),
	sp("trestle.appauth.login", "POST", "/api/v1/auth/login", "app-auth", "login", operation.Mutation, operation.Public, "internal/appauth/handler_test.go"),
	sp("trestle.appauth.refresh", "POST", "/api/v1/auth/refresh", "app-auth", "refresh", operation.Mutation, operation.Public, "internal/appauth/handler_test.go"),
	sp("trestle.appauth.logout", "POST", "/api/v1/auth/logout", "app-auth", "logout", operation.Destructive, operation.Service, "internal/appauth/handler_test.go"),
	sp("trestle.collections.list", "GET", "/admin/v1/collections", "collections", "list", operation.Read, operation.Session, "internal/collections/handler_test.go"),
	sp("trestle.collections.create", "POST", "/admin/v1/collections", "collections", "create", operation.Mutation, operation.Session, "internal/collections/handler_test.go"),
	sp("trestle.collections.get", "GET", "/admin/v1/collections/{name}", "collections", "get", operation.Read, operation.Session, "internal/collections/handler_test.go"),
	sp("trestle.collections.update", "PATCH", "/admin/v1/collections/{name}", "collections", "update", operation.Mutation, operation.Session, "internal/collections/handler_test.go"),
	sp("trestle.collections.delete", "DELETE", "/admin/v1/collections/{name}", "collections", "delete", operation.Destructive, operation.Session, "internal/collections/handler_test.go"),
	sp("trestle.records.list", "GET", "/api/v1/collections/{collection}/records", "records", "list", operation.Read, operation.Service, "internal/records/handler_test.go"),
	sp("trestle.records.create", "POST", "/api/v1/collections/{collection}/records", "records", "create", operation.Mutation, operation.Service, "internal/records/handler_test.go"),
	sp("trestle.records.get", "GET", "/api/v1/collections/{collection}/records/{id}", "records", "get", operation.Read, operation.Service, "internal/records/handler_test.go"),
	sp("trestle.records.update", "PATCH", "/api/v1/collections/{collection}/records/{id}", "records", "update", operation.Mutation, operation.Service, "internal/records/handler_test.go"),
	sp("trestle.records.delete", "DELETE", "/api/v1/collections/{collection}/records/{id}", "records", "delete", operation.Destructive, operation.Service, "internal/records/handler_test.go"),
	sp("trestle.records.batch", "POST", "/api/v1/collections/{collection}/records/batch", "records", "batch", operation.Mutation, operation.Service, "internal/records/rollback_test.go"),
	sp("trestle.files.upload", "POST", "/api/v1/files", "files", "upload", operation.Mutation, operation.Service, "internal/files/handler_test.go"),
	sp("trestle.files.get", "GET", "/api/v1/files/{id}", "files", "get", operation.Read, operation.Service, "internal/files/handler_test.go"),
	sp("trestle.files.delete", "DELETE", "/api/v1/files/{id}", "files", "delete", operation.Destructive, operation.Service, "internal/files/deletion_test.go"),
	{id: "trestle.realtime.stream", method: "GET", path: "/api/v1/realtime", resource: "events", verb: "stream", kind: operation.Read, boundary: operation.Service, test: "internal/events/handler_test.go", automation: operation.StreamingProtocol, website: false},
	sp("trestle.openapi.read", "GET", "/api/v1/openapi.json", "api", "openapi", operation.Read, operation.Public, "internal/apidocs/handler_test.go"),
	sp("trestle.capabilities.read", "GET", "/api/v1/capabilities", "api", "capabilities", operation.Read, operation.Public, "internal/apidocs/handler_test.go"),
	sp("trestle.app-users.list", "GET", "/admin/v1/app-users", "app-users", "list", operation.Read, operation.Session, "internal/appauth/handler_test.go"),
	sp("trestle.app-users.disable", "POST", "/admin/v1/app-users/{id}/disable", "app-users", "disable", operation.Destructive, operation.Session, "internal/appauth/handler_test.go"),
	sp("trestle.registration.read", "GET", "/admin/v1/app-registration", "registration", "get", operation.Read, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.policy.update", "PUT", "/admin/v1/app-registration/policy", "registration", "set-policy", operation.Mutation, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.activation-url.read", "GET", "/admin/v1/app-registration/activation-base-url", "registration", "activation-url", operation.Read, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.activation-url.update", "PUT", "/admin/v1/app-registration/activation-base-url", "registration", "set-activation-url", operation.Mutation, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.invitations.list", "GET", "/admin/v1/app-registration/invitations", "invitations", "list", operation.Read, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.invitations.create", "POST", "/admin/v1/app-registration/invitations", "invitations", "create", operation.Mutation, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.invitations.revoke", "POST", "/admin/v1/app-registration/invitations/{id}/revoke", "invitations", "revoke", operation.Destructive, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.requests.list", "GET", "/admin/v1/app-registration/requests", "access-requests", "list", operation.Read, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.requests.approve", "POST", "/admin/v1/app-registration/requests/{id}/approve", "access-requests", "approve", operation.Mutation, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.requests.reject", "POST", "/admin/v1/app-registration/requests/{id}/reject", "access-requests", "reject", operation.Destructive, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.registration.requests.reissue", "POST", "/admin/v1/app-registration/requests/{id}/reissue", "access-requests", "reissue", operation.Mutation, operation.Session, "internal/appauth/registration_test.go"),
	sp("trestle.credentials.list", "GET", "/admin/v1/credentials", "credentials", "list", operation.Read, operation.Session, "internal/identities/handler_test.go"),
	sp("trestle.credentials.create", "POST", "/admin/v1/credentials", "credentials", "create", operation.Mutation, operation.Session, "internal/identities/handler_test.go"),
	sp("trestle.credentials.revoke", "DELETE", "/admin/v1/credentials/{id}", "credentials", "revoke", operation.Destructive, operation.Session, "internal/identities/handler_test.go"),
	sp("trestle.rules.get", "GET", "/admin/v1/collection-rules/{collection}", "rules", "get", operation.Read, operation.Session, "internal/rules/handler_test.go"),
	sp("trestle.rules.update", "PUT", "/admin/v1/collection-rules/{collection}", "rules", "update", operation.Mutation, operation.Session, "internal/rules/handler_test.go"),
	sp("trestle.rules.explain", "POST", "/admin/v1/collection-rules/{collection}/explain", "rules", "explain", operation.Read, operation.Session, "internal/rules/handler_test.go"),
	sp("trestle.files.admin.list", "GET", "/admin/v1/files", "admin-files", "list", operation.Read, operation.Session, "internal/files/handler_test.go"),
	sp("trestle.files.cleanup", "POST", "/admin/v1/files/cleanup", "admin-files", "cleanup", operation.Destructive, operation.Session, "internal/files/deletion_test.go"),
	sp("trestle.storage.status", "GET", "/admin/v1/storage/status", "storage", "status", operation.Read, operation.Session, "internal/files/handler_test.go"),
	sp("trestle.events.list", "GET", "/admin/v1/events", "events", "list", operation.Read, operation.Session, "internal/events/handler_test.go"),
	sp("trestle.audit.list", "GET", "/admin/v1/audit", "audit", "list", operation.Read, operation.Capability, "internal/audit/handler_test.go"),
	sp("trestle.operations.read", "GET", "/admin/v1/operations", "operations", "get", operation.Read, operation.Capability, "internal/audit/handler_test.go"),
	sp("trestle.jobs.list", "GET", "/admin/v1/jobs", "jobs", "list", operation.Read, operation.Session, "internal/jobs/list_endpoint_test.go"),
	sp("trestle.jobs.create", "POST", "/admin/v1/jobs", "jobs", "create", operation.Mutation, operation.Session, "internal/jobs/handler_test.go"),
	sp("trestle.jobs.action", "POST", "/admin/v1/jobs/{id}", "jobs", "action", operation.Mutation, operation.Session, "internal/jobs/retry_deadletter_test.go"),
	sp("trestle.webhooks.list", "GET", "/admin/v1/webhooks", "webhooks", "list", operation.Read, operation.Session, "internal/webhooks/handler_test.go"),
	sp("trestle.webhooks.create", "POST", "/admin/v1/webhooks", "webhooks", "create", operation.Mutation, operation.Session, "internal/webhooks/handler_test.go"),
	sp("trestle.webhooks.action", "POST", "/admin/v1/webhooks/{id}", "webhooks", "action", operation.Mutation, operation.Session, "internal/webhooks/handler_test.go"),
	sp("trestle.functions.list", "GET", "/admin/v1/functions", "functions", "list", operation.Read, operation.Session, "internal/functions/target_validation_test.go"),
	sp("trestle.functions.create", "POST", "/admin/v1/functions", "functions", "create", operation.Mutation, operation.Session, "internal/functions/target_validation_test.go"),
	sp("trestle.functions.action", "POST", "/admin/v1/functions/{id}", "functions", "action", operation.Mutation, operation.Session, "internal/functions/target_validation_test.go"),
	sp("trestle.api.schema", "GET", "/admin/v1/api/schema", "api", "schema", operation.Read, operation.Session, "internal/apidocs/handler_test.go"),
	sp("trestle.backups.list", "GET", "/admin/v1/backups", "backups", "list", operation.Read, operation.Session, "internal/backup/handler_test.go"),
	sp("trestle.backups.create", "POST", "/admin/v1/backups", "backups", "create", operation.Mutation, operation.Session, "internal/backup/handler_test.go"),
	sp("trestle.backups.get", "GET", "/admin/v1/backups/{id}", "backups", "get", operation.Read, operation.Session, "internal/backup/handler_test.go"),
	sp("trestle.restores.preflight", "POST", "/admin/v1/restores/preflight", "restores", "preflight", operation.Read, operation.Session, "internal/backup/restore_test.go"),
	sp("trestle.export.read", "GET", "/admin/v1/export", "data", "export", operation.Read, operation.Session, "internal/backup/portable_test.go"),
	sp("trestle.import.dry-run", "POST", "/admin/v1/imports/dry-run", "data", "import-dry-run", operation.Read, operation.Session, "internal/backup/portable_test.go"),
	sp("trestle.deployment.read", "GET", "/admin/v1/deployment", "deployment", "get", operation.Read, operation.Session, "internal/deployment/handler_test.go"),
	sp("trestle.support-bundle.read", "GET", "/admin/v1/support-bundle", "support-bundle", "get", operation.Read, operation.Session, "internal/deployment/handler_test.go"),
}

func prepareSpecs() {
	// Cluster management uses the proven Gantry lifecycle while remaining Trestle-owned persistence/policy.
	cluster := []spec{
		sp("trestle.cluster.identity", "GET", "/admin/v1/cluster/identity", "cluster", "identity", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.members", "GET", "/admin/v1/cluster/members", "cluster", "members", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.invite", "POST", "/admin/v1/cluster/invitations", "cluster", "invite", operation.Mutation, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.joins", "GET", "/admin/v1/cluster/joins", "cluster", "joins", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.approve", "POST", "/admin/v1/cluster/joins/{id}/approve", "cluster", "approve", operation.Mutation, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.reject", "POST", "/admin/v1/cluster/joins/{id}/reject", "cluster", "reject", operation.Destructive, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.outbound", "GET", "/admin/v1/cluster/outbound", "cluster", "outbound", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.join", "POST", "/admin/v1/cluster/outbound", "cluster", "join", operation.Mutation, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.collect", "POST", "/admin/v1/cluster/outbound/{id}/collect", "cluster", "collect", operation.Mutation, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.audit", "GET", "/admin/v1/cluster/audit", "cluster", "audit", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.status", "GET", "/admin/v1/cluster/summary", "cluster", "status", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
		sp("trestle.cluster.compare", "GET", "/admin/v1/cluster/compare", "cluster", "compare", operation.Read, operation.Capability, "internal/cluster/cluster_test.go"),
	}
	for _, action := range []string{"enable", "disable", "rotate", "revoke", "remove"} {
		kind := operation.Mutation
		if action == "revoke" || action == "remove" {
			kind = operation.Destructive
		}
		cluster = append(cluster, sp("trestle.cluster.member."+action, "POST", "/admin/v1/cluster/members/{id}/"+action, "cluster", action, kind, operation.Capability, "internal/cluster/cluster_test.go"))
	}
	specs = append(specs, cluster...)
	for i := range specs {
		if specs[i].boundary == operation.Capability && specs[i].capability == "" {
			specs[i].capability = "admin.manage"
		}
		switch specs[i].id {
		case "trestle.launcher.config.update":
			specs[i].capability = "launcher.configure.all"
		case "trestle.admin.users.list", "trestle.admin.users.manage":
			specs[i].capability = "accounts.manage"
		case "trestle.admin.roles.list", "trestle.admin.roles.update":
			specs[i].capability = "roles.manage"
		case "trestle.audit.list", "trestle.operations.read":
			specs[i].capability = "audit.read"
		}
		if strings.HasPrefix(specs[i].id, "trestle.cluster.") {
			specs[i].capability = "cluster.manage"
		}
		switch specs[i].id {
		case "trestle.admin.setup.apply", "trestle.admin.session.login", "trestle.admin.password.update", "trestle.appauth.register", "trestle.appauth.login":
			specs[i].secrets = []string{"/password"}
		case "trestle.appauth.refresh":
			specs[i].secrets = []string{"/refreshToken"}
		case "trestle.credentials.create":
			specs[i].secrets = []string{"/secret"}
		}
	}
}

var Contracts = func() []operation.Contract { prepareSpecs(); return buildContracts() }()

func buildContracts() []operation.Contract {
	out := make([]operation.Contract, 0, len(specs))
	for _, x := range specs {
		var cli *operation.CLI
		if x.resource != "" {
			cli = &operation.CLI{Resource: x.resource, Verb: x.verb, Implemented: true}
		}
		auth := operation.Authorization{Boundary: x.boundary}
		if x.boundary == operation.Capability {
			auth.Capability = x.capability
		}
		audit := operation.Audit{}
		if x.kind != operation.Read {
			audit = operation.Audit{Required: true, Event: x.id + ".performed"}
		}
		schemas := operation.Schemas{Output: x.id + ".response.v1"}
		if x.kind != operation.Read {
			schemas.Input = x.id + ".request.v1"
		}
		out = append(out, operation.Contract{SchemaVersion: operation.SchemaVersion, ID: x.id, Kind: x.kind, Route: operation.Route{Method: x.method, Path: x.path}, CLI: cli, Authorization: auth, Schemas: schemas, Audit: audit, Idempotency: operation.Idempotency{RetrySafe: x.kind == operation.Read}, Automation: x.automation, SecretInputs: append([]string(nil), x.secrets...)})
	}
	return out
}
func Manifest() contracttest.Manifest {
	routes := make([]operation.Route, 0, len(Contracts))
	commands := make([]operation.CLI, 0, len(Contracts))
	ids := make([]string, 0, len(Contracts))
	evidence := map[string]contracttest.Evidence{}
	for i, c := range Contracts {
		routes = append(routes, c.Route)
		if c.CLI != nil && c.CLI.Implemented {
			commands = append(commands, *c.CLI)
		}
		if specs[i].website {
			ids = append(ids, c.ID)
		}
		evidence[c.ID] = contracttest.Evidence{Website: specs[i].website, Tests: []string{specs[i].test}}
	}
	return contracttest.Manifest{SchemaVersion: 1, Project: "trestle", Operations: Contracts, ObservedRoutes: routes, ObservedCommands: commands, WebsiteOperations: ids, Evidence: evidence}
}
func AdoptionManifest() contracttest.Manifest { return Manifest() }
