package storage

import (
	"context"
	"database/sql"
	"fmt"

	"sentinel/backend/internal/model"
)

func (s *SQLStore) ListHosts(ctx context.Context) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, address, port, environment, criticality, created_at FROM hosts ORDER BY environment, name`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	hosts := make([]model.Host, 0)
	for rows.Next() {
		var host model.Host
		if err := rows.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.Environment, &host.Criticality, &host.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hosts: %w", err)
	}
	return hosts, nil
}

func (s *SQLStore) CreateHost(ctx context.Context, host model.Host) error {
	if _, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO hosts (id, name, address, port, environment, criticality, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`), host.ID, host.Name, host.Address, host.Port, host.Environment, host.Criticality, host.CreatedAt); err != nil {
		return fmt.Errorf("insert host: %w", err)
	}
	return nil
}

func (s *SQLStore) ListPoliciesByHost(ctx context.Context, hostID string) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, role_id, host_id, can_connect, require_mfa, created_at FROM policies WHERE host_id = ? ORDER BY created_at DESC`), hostID)
	if err != nil {
		return nil, fmt.Errorf("list policies by host: %w", err)
	}
	defer rows.Close()

	policies := make([]model.Policy, 0)
	for rows.Next() {
		var policy model.Policy
		if err := rows.Scan(&policy.ID, &policy.RoleID, &policy.HostID, &policy.CanConnect, &policy.RequireMFA, &policy.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}
	return policies, nil
}

func (s *SQLStore) ReplaceHostPolicies(ctx context.Context, hostID string, policies []model.Policy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin replace host policies transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM policies WHERE host_id = ?`), hostID); err != nil {
		return fmt.Errorf("delete host policies: %w", err)
	}
	for _, policy := range policies {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO policies (id, role_id, host_id, can_connect, require_mfa, created_at) VALUES (?, ?, ?, ?, ?, ?)`), policy.ID, policy.RoleID, policy.HostID, policy.CanConnect, policy.RequireMFA, policy.CreatedAt); err != nil {
			return fmt.Errorf("insert host policy: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace host policies: %w", err)
	}
	return nil
}

func (s *SQLStore) HasHostAccess(ctx context.Context, userID, hostID string) (bool, error) {
	query := s.bind(`
		SELECT COUNT(1)
		FROM policies p
		JOIN user_roles ur ON ur.role_id = p.role_id
		WHERE ur.user_id = ? AND p.host_id = ? AND p.can_connect = TRUE`)

	var count int
	if err := s.db.QueryRowContext(ctx, query, userID, hostID).Scan(&count); err != nil {
		return false, fmt.Errorf("check host access: %w", err)
	}
	return count > 0, nil
}

func (s *SQLStore) hostExists(ctx context.Context, hostID string) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id FROM hosts WHERE id = ?`), hostID).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check host existence: %w", err)
	}
	return true, nil
}
