package store

var postgresMigrations = map[int]string{
	1: `
CREATE TABLE _trestle_schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);
CREATE TABLE _trestle_system_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE _trestle_audit (id BIGSERIAL PRIMARY KEY, occurred_at TEXT NOT NULL, actor_kind TEXT NOT NULL, actor_id TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL, request_id TEXT);`,
	2: `
CREATE TABLE _trestle_admins (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, disabled_at TEXT);
CREATE TABLE _trestle_admin_sessions (id TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES _trestle_admins(id) ON DELETE CASCADE, token_hash BYTEA NOT NULL UNIQUE, csrf_hash BYTEA NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE INDEX _trestle_admin_sessions_admin ON _trestle_admin_sessions(admin_id);`,
	3: `
CREATE TABLE _trestle_collections (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL CHECK(kind IN ('base')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE _trestle_fields (id TEXT PRIMARY KEY, collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE, position INTEGER NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, required BOOLEAN NOT NULL, is_unique BOOLEAN NOT NULL, default_json TEXT, created_at TEXT NOT NULL, UNIQUE(collection_id,name), UNIQUE(collection_id,position));`,
	4: `CREATE TABLE _trestle_record_idempotency (collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE, idempotency_key TEXT NOT NULL, record_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(collection_id,idempotency_key));`,
	5: `
CREATE TABLE _trestle_app_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, verified_at TEXT, disabled_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE _trestle_app_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES _trestle_app_users(id) ON DELETE CASCADE, refresh_hash BYTEA NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, replaced_by TEXT);
CREATE INDEX _trestle_app_sessions_user ON _trestle_app_sessions(user_id);`,
	6: `
CREATE TABLE _trestle_credentials (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('service','personal')), name TEXT NOT NULL, owner_admin_id TEXT REFERENCES _trestle_admins(id) ON DELETE CASCADE, secret_hash BYTEA NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);
CREATE INDEX _trestle_credentials_kind ON _trestle_credentials(kind);`,
	7: `
CREATE TABLE _trestle_app_access (token_hash BYTEA PRIMARY KEY, session_id TEXT NOT NULL REFERENCES _trestle_app_sessions(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES _trestle_app_users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL);
CREATE TABLE _trestle_collection_rules (collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE, operation TEXT NOT NULL CHECK(operation IN ('list','view','create','update','delete')), expression TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(collection_id,operation));`,
	8: `
CREATE TABLE _trestle_files (id TEXT PRIMARY KEY, storage_key TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL, content_type TEXT NOT NULL, size BIGINT NOT NULL CHECK(size >= 0), sha256 TEXT NOT NULL, collection_name TEXT, record_id TEXT, created_at TEXT NOT NULL);
CREATE INDEX _trestle_files_record ON _trestle_files(collection_name,record_id);`,
	9: `
CREATE TABLE _trestle_events (sequence BIGSERIAL PRIMARY KEY, occurred_at TEXT NOT NULL, topic TEXT NOT NULL, collection_name TEXT, record_id TEXT, payload_json TEXT NOT NULL);
CREATE INDEX _trestle_events_topic_sequence ON _trestle_events(topic,sequence);`,
	10: `
ALTER TABLE _trestle_audit ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';
CREATE INDEX _trestle_audit_occurred ON _trestle_audit(occurred_at DESC,id DESC);
CREATE INDEX _trestle_audit_action ON _trestle_audit(action,id DESC);`,
	11: `
CREATE TABLE _trestle_jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','cancelled','dead')), attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 5, available_at TEXT NOT NULL, lease_until TEXT, idempotency_key TEXT UNIQUE, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX _trestle_jobs_claim ON _trestle_jobs(status,available_at,id);`,
	12: `CREATE TABLE _trestle_webhooks (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, topics TEXT NOT NULL, secret_cipher BYTEA NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`,
	13: `CREATE TABLE _trestle_functions (id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL CHECK(provider='aws-lambda'), target TEXT NOT NULL, region TEXT NOT NULL, topics TEXT NOT NULL, callback_scopes TEXT NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`,
	14: `
CREATE TABLE _trestle_file_deletions (id TEXT PRIMARY KEY, storage_key TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','done')), attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, finalized_at TEXT);
ALTER TABLE _trestle_files ADD COLUMN deleted_at TEXT;`,
	15: `
CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL);
CREATE TABLE _trestle_app_invitations (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('self_register','activate')), email TEXT NOT NULL, token_hash BYTEA NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, revoked_at TEXT, created_by_admin_id TEXT, user_id TEXT, access_request_id TEXT);
CREATE INDEX _trestle_app_invitations_email ON _trestle_app_invitations(email);
CREATE TABLE _trestle_app_access_requests (id TEXT PRIMARY KEY, email TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','expired')), created_at TEXT NOT NULL, decided_at TEXT, decided_by_admin_id TEXT);
CREATE UNIQUE INDEX _trestle_app_access_requests_pending_email ON _trestle_app_access_requests(email) WHERE status = 'pending';`,
	16: `
CREATE TABLE _trestle_roles (id TEXT PRIMARY KEY, name TEXT NOT NULL, capabilities_json TEXT NOT NULL, built_in BOOLEAN NOT NULL);
CREATE TABLE _trestle_admin_roles (admin_id TEXT NOT NULL REFERENCES _trestle_admins(id) ON DELETE CASCADE, role_id TEXT NOT NULL REFERENCES _trestle_roles(id) ON DELETE RESTRICT, PRIMARY KEY(admin_id,role_id));
INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES('administrator','Administrator','["*"]',TRUE);
INSERT INTO _trestle_admin_roles(admin_id,role_id) SELECT id,'administrator' FROM _trestle_admins;`,
	17: `CREATE TABLE _trestle_launcher_instances (id TEXT PRIMARY KEY, position INTEGER NOT NULL UNIQUE, name TEXT NOT NULL, domain TEXT NOT NULL, port INTEGER CHECK(port BETWEEN 1 AND 65535));`,
	18: `
CREATE TABLE _trestle_cluster_identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), node_id TEXT NOT NULL UNIQUE, installation_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL DEFAULT '', public_key BYTEA NOT NULL, private_key BYTEA NOT NULL, capabilities_json TEXT NOT NULL, protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE _trestle_cluster_members (node_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL, public_key BYTEA NOT NULL, capabilities_json TEXT NOT NULL, protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')), outbound_secret TEXT NOT NULL, inbound_secret_hash BYTEA NOT NULL, credential_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, paired_at TEXT NOT NULL, last_seen_at TEXT, last_latency_ms BIGINT, revoked_at TEXT);
CREATE TABLE _trestle_cluster_invitations (id TEXT PRIMARY KEY, token_hash BYTEA NOT NULL UNIQUE, state TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);`,
	19: `CREATE TABLE _trestle_cluster_nonces (node_id TEXT NOT NULL REFERENCES _trestle_cluster_members(node_id) ON DELETE CASCADE, nonce TEXT NOT NULL, seen_at TEXT NOT NULL, PRIMARY KEY(node_id,nonce)); CREATE INDEX _trestle_cluster_nonces_seen ON _trestle_cluster_nonces(seen_at);`,
	20: `CREATE TABLE _trestle_cluster_join_requests (id TEXT PRIMARY KEY, request_secret_hash BYTEA NOT NULL UNIQUE, invitation_id TEXT NOT NULL REFERENCES _trestle_cluster_invitations(id), node_id TEXT NOT NULL, installation_id TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', public_endpoint TEXT NOT NULL, public_key BYTEA NOT NULL, capabilities_json TEXT NOT NULL DEFAULT '[]', protocol_version INTEGER NOT NULL, product_version TEXT NOT NULL DEFAULT '', credential_for_local TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, decided_at TEXT, response_consumed_at TEXT); CREATE TABLE _trestle_cluster_outbound_joins (id TEXT PRIMARY KEY, remote_url TEXT NOT NULL, request_id TEXT NOT NULL, request_secret TEXT NOT NULL, local_inbound_credential TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '');`, 21: `CREATE TABLE _trestle_propagation_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, selector_json TEXT NOT NULL, kinds_json TEXT NOT NULL, mode TEXT NOT NULL, schedule TEXT NOT NULL DEFAULT '', maintenance_window TEXT NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL); CREATE TABLE _trestle_propagation_history (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, rolled_back INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL); CREATE INDEX _trestle_propagation_history_created ON _trestle_propagation_history(created_at DESC);`,
	22: `ALTER TABLE _trestle_propagation_profiles ADD COLUMN last_run_at TEXT;`,
	23: `
ALTER TABLE _trestle_admins ADD COLUMN username TEXT;
UPDATE _trestle_admins SET username = split_part(email, '@', 1) WHERE username IS NULL OR trim(username) = '';`,
}
