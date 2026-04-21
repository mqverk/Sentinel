package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"

	"sentinel/backend/internal/config"
	"sentinel/backend/internal/model"
)

type SQLStore struct {
	db     *sql.DB
	driver string
}

func newSQLStore(cfg config.DatabaseConfig) (*SQLStore, error) {
	driver := strings.ToLower(cfg.Driver)
	sqlDriver := "sqlite3"
	if driver == "postgres" {
		sqlDriver = "pgx"
	}

	db, err := sql.Open(sqlDriver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	store := &SQLStore{db: db, driver: driver}
	if err := store.Ping(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

func (s *SQLStore) Close() error {
	return s.db.Close()
}

func (s *SQLStore) RunMigrations(ctx context.Context) error {
	for _, query := range migrations {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("run migration: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) Seed(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	roles := []model.Role{
		{ID: "role-admin", Name: "admin", Description: "Full system control", CreatedAt: now},
		{ID: "role-operator", Name: "operator", Description: "Operational bastion access", CreatedAt: now},
		{ID: "role-auditor", Name: "auditor", Description: "Read-only audit access", CreatedAt: now},
	}
	for _, role := range roles {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO roles (id, name, description, created_at) VALUES (?, ?, ?, ?)`), role.ID, role.Name, role.Description, role.CreatedAt)
		if err != nil && !isUniqueViolation(err) {
			return fmt.Errorf("seed roles: %w", err)
		}
	}

	permissions := []model.Permission{
		{ID: "perm-dashboard-view", Resource: "dashboard", Action: "view", Description: "View dashboard", CreatedAt: now},
		{ID: "perm-users-read", Resource: "users", Action: "read", Description: "View users", CreatedAt: now},
		{ID: "perm-users-write", Resource: "users", Action: "write", Description: "Manage users", CreatedAt: now},
		{ID: "perm-roles-read", Resource: "roles", Action: "read", Description: "View roles", CreatedAt: now},
		{ID: "perm-roles-write", Resource: "roles", Action: "write", Description: "Manage roles", CreatedAt: now},
		{ID: "perm-sessions-read", Resource: "sessions", Action: "read", Description: "View sessions", CreatedAt: now},
		{ID: "perm-sessions-replay", Resource: "sessions", Action: "replay", Description: "Replay sessions", CreatedAt: now},
		{ID: "perm-sessions-terminate", Resource: "sessions", Action: "terminate", Description: "Terminate sessions", CreatedAt: now},
		{ID: "perm-audit-read", Resource: "audit", Action: "read", Description: "View audit logs", CreatedAt: now},
		{ID: "perm-hosts-read", Resource: "hosts", Action: "read", Description: "View hosts", CreatedAt: now},
		{ID: "perm-hosts-write", Resource: "hosts", Action: "write", Description: "Manage hosts", CreatedAt: now},
		{ID: "perm-settings-read", Resource: "settings", Action: "read", Description: "View settings", CreatedAt: now},
		{ID: "perm-settings-write", Resource: "settings", Action: "write", Description: "Manage settings", CreatedAt: now},
	}
	for _, perm := range permissions {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO permissions (id, resource, action, description, created_at) VALUES (?, ?, ?, ?, ?)`), perm.ID, perm.Resource, perm.Action, perm.Description, perm.CreatedAt)
		if err != nil && !isUniqueViolation(err) {
			return fmt.Errorf("seed permissions: %w", err)
		}
	}

	adminPermIDs := make([]string, 0, len(permissions))
	for _, perm := range permissions {
		adminPermIDs = append(adminPermIDs, perm.ID)
	}
	if err := s.replaceRolePermissionsTx(ctx, tx, "role-admin", adminPermIDs); err != nil {
		return fmt.Errorf("seed admin role permissions: %w", err)
	}
	if err := s.replaceRolePermissionsTx(ctx, tx, "role-operator", []string{"perm-dashboard-view", "perm-sessions-read", "perm-sessions-replay", "perm-hosts-read"}); err != nil {
		return fmt.Errorf("seed operator role permissions: %w", err)
	}
	if err := s.replaceRolePermissionsTx(ctx, tx, "role-auditor", []string{"perm-audit-read", "perm-sessions-read", "perm-sessions-replay", "perm-dashboard-view"}); err != nil {
		return fmt.Errorf("seed auditor role permissions: %w", err)
	}

	var existingAdminID string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT id FROM users WHERE username = ?`), "admin").Scan(&existingAdminID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check admin user: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte("Sentinel!ChangeMe"), bcrypt.DefaultCost)
		if hashErr != nil {
			return fmt.Errorf("hash admin password: %w", hashErr)
		}
		adminID := uuid.NewString()
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO users (id, username, email, password_hash, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`), adminID, "admin", "admin@sentinel.local", string(hash), false, now)
		if err != nil {
			return fmt.Errorf("insert admin user: %w", err)
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`), adminID, "role-admin")
		if err != nil {
			return fmt.Errorf("assign admin role: %w", err)
		}
	}

	hosts := []model.Host{
		{ID: "host-core-db", Name: "core-db", Address: "10.0.1.10", Port: 22, Environment: "prod", Criticality: "critical", CreatedAt: now},
		{ID: "host-api-node-1", Name: "api-node-1", Address: "10.0.2.15", Port: 22, Environment: "staging", Criticality: "high", CreatedAt: now},
	}
	for _, host := range hosts {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO hosts (id, name, address, port, environment, criticality, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`), host.ID, host.Name, host.Address, host.Port, host.Environment, host.Criticality, host.CreatedAt)
		if err != nil && !isUniqueViolation(err) {
			return fmt.Errorf("seed hosts: %w", err)
		}
	}

	defaultPolicies := []model.Policy{
		{ID: uuid.NewString(), RoleID: "role-admin", HostID: "host-core-db", CanConnect: true, RequireMFA: true, CreatedAt: now},
		{ID: uuid.NewString(), RoleID: "role-admin", HostID: "host-api-node-1", CanConnect: true, RequireMFA: true, CreatedAt: now},
		{ID: uuid.NewString(), RoleID: "role-operator", HostID: "host-api-node-1", CanConnect: true, RequireMFA: true, CreatedAt: now},
	}
	for _, policy := range defaultPolicies {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO policies (id, role_id, host_id, can_connect, require_mfa, created_at) VALUES (?, ?, ?, ?, ?, ?)`), policy.ID, policy.RoleID, policy.HostID, policy.CanConnect, policy.RequireMFA, policy.CreatedAt)
		if err != nil && !isUniqueViolation(err) {
			return fmt.Errorf("seed policies: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)`), "session.retentionDays", `{"value":30}`, now); err != nil && !isUniqueViolation(err) {
		return fmt.Errorf("seed settings retention: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)`), "security.allowedCIDRs", `{"value":[]}`, now); err != nil && !isUniqueViolation(err) {
		return fmt.Errorf("seed settings cidr: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit seed transaction: %w", err)
	}

	return nil
}

func (s *SQLStore) bind(query string) string {
	if s.driver != "postgres" {
		return query
	}

	var builder strings.Builder
	arg := 1
	for _, ch := range query {
		if ch == '?' {
			builder.WriteString(fmt.Sprintf("$%d", arg))
			arg++
			continue
		}
		builder.WriteRune(ch)
	}
	return builder.String()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "unique") || strings.Contains(value, "duplicate")
}
