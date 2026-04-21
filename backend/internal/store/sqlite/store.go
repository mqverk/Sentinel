package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

const (
	roleAdminID    = "role-admin"
	roleOperatorID = "role-operator"
	roleAnalystID  = "role-analyst"
)

var schema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	display_name TEXT NOT NULL,
	disabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
	role_id TEXT NOT NULL,
	permission TEXT NOT NULL,
	PRIMARY KEY (role_id, permission),
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_roles (
	user_id TEXT NOT NULL,
	role_id TEXT NOT NULL,
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	address TEXT NOT NULL,
	port INTEGER NOT NULL,
	environment TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	UNIQUE(address, port)
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	username TEXT NOT NULL,
	host_id TEXT NOT NULL,
	host_name TEXT NOT NULL,
	source_ip TEXT NOT NULL,
	protocol TEXT NOT NULL,
	status TEXT NOT NULL,
	started_at INTEGER NOT NULL,
	ended_at INTEGER,
	replay TEXT NOT NULL DEFAULT '',
	FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp INTEGER NOT NULL,
	actor_id TEXT NOT NULL,
	actor_username TEXT NOT NULL,
	action TEXT NOT NULL,
	resource TEXT NOT NULL,
	result TEXT NOT NULL,
	source_ip TEXT NOT NULL,
	metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at DESC);

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
`

type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db  *sql.DB
	log *slog.Logger
}

func New(dsn string, log *slog.Logger) (store.Store, error) {
	if dsn == "" {
		dsn = "sentinel.db"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, log: log}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) Seed(ctx context.Context, data store.SeedData) error {
	if data.AdminUsername == "" || data.AdminPasswordHash == "" {
		return errors.New("seed data is missing admin credentials")
	}

	adminRole := domain.Role{
		ID:          roleAdminID,
		Name:        "admin",
		Description: "Global administrative access",
		Permissions: []string{"*"},
	}

	operatorRole := domain.Role{
		ID:          roleOperatorID,
		Name:        "operator",
		Description: "Operators can connect to approved hosts and inspect sessions",
		Permissions: []string{"dashboard:read", "sessions:read", "sessions:write", "hosts:read", "hosts:connect"},
	}

	analystRole := domain.Role{
		ID:          roleAnalystID,
		Name:        "analyst",
		Description: "Security analysts can review telemetry and audit records",
		Permissions: []string{"dashboard:read", "sessions:read", "audit:read", "hosts:read"},
	}

	for _, role := range []domain.Role{adminRole, operatorRole, analystRole} {
		if err := s.ensureRole(ctx, role); err != nil {
			return err
		}
	}

	adminUser, err := s.GetUserByUsername(ctx, data.AdminUsername)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		now := time.Now().UTC()
		adminUser = domain.User{
			ID:           uuid.NewString(),
			Username:     data.AdminUsername,
			PasswordHash: data.AdminPasswordHash,
			DisplayName:  data.AdminDisplayName,
			Disabled:     false,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		if err := s.CreateUser(ctx, adminUser); err != nil {
			return err
		}
	}

	if err := s.SetUserRoles(ctx, adminUser.ID, []string{roleAdminID}); err != nil {
		return err
	}

	return nil
}

func (s *Store) ensureRole(ctx context.Context, role domain.Role) error {
	existing, err := s.GetRoleByID(ctx, role.ID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		now := time.Now().UTC()
		role.CreatedAt = now
		role.UpdatedAt = now
		return s.CreateRole(ctx, role)
	}

	existing.Name = role.Name
	existing.Description = role.Description
	existing.Permissions = role.Permissions
	existing.UpdatedAt = time.Now().UTC()

	return s.UpdateRole(ctx, existing)
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}

	if limit > 500 {
		return 500
	}

	return limit
}

func toUnix(t time.Time) int64 {
	return t.UTC().Unix()
}

func fromUnix(ts int64) time.Time {
	return time.Unix(ts, 0).UTC()
}

func (s *Store) rolePermissions(ctx context.Context, q dbtx, roleID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission ASC`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := make([]string, 0, 8)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, rows.Err()
}

func (s *Store) replaceRolePermissions(ctx context.Context, tx *sql.Tx, roleID string, permissions []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = ?`, roleID); err != nil {
		return err
	}

	for _, permission := range permissions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)`, roleID, permission); err != nil {
			return err
		}
	}

	return nil
}
