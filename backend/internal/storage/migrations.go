package storage

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		disabled BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP NOT NULL,
		last_login_at TIMESTAMP NULL
	);`,
	`CREATE TABLE IF NOT EXISTS roles (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS permissions (
		id TEXT PRIMARY KEY,
		resource TEXT NOT NULL,
		action TEXT NOT NULL,
		description TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		UNIQUE(resource, action)
	);`,
	`CREATE TABLE IF NOT EXISTS user_roles (
		user_id TEXT NOT NULL,
		role_id TEXT NOT NULL,
		PRIMARY KEY (user_id, role_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
	);`,
	`CREATE TABLE IF NOT EXISTS role_permissions (
		role_id TEXT NOT NULL,
		permission_id TEXT NOT NULL,
		PRIMARY KEY (role_id, permission_id),
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
	);`,
	`CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		address TEXT NOT NULL,
		port INTEGER NOT NULL,
		environment TEXT NOT NULL,
		criticality TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS policies (
		id TEXT PRIMARY KEY,
		role_id TEXT NOT NULL,
		host_id TEXT NOT NULL,
		can_connect BOOLEAN NOT NULL DEFAULT TRUE,
		require_mfa BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		UNIQUE(role_id, host_id)
	);`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		host_id TEXT NOT NULL,
		status TEXT NOT NULL,
		started_at TIMESTAMP NOT NULL,
		ended_at TIMESTAMP NULL,
		recording_path TEXT NOT NULL,
		metadata_json TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (host_id) REFERENCES hosts(id)
	);`,
	`CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		actor_id TEXT NOT NULL,
		actor_username TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		outcome TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		details_json TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value_json TEXT NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);`,
	`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);`,
	`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);`,
}
