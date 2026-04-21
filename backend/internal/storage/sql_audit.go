package storage

import (
	"context"
	"fmt"
	"time"

	"sentinel/backend/internal/model"
)

func (s *SQLStore) CreateAuditLog(ctx context.Context, log model.AuditLog) error {
	query := s.bind(`INSERT INTO audit_logs (id, actor_id, actor_username, action, resource, outcome, source_ip, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := s.db.ExecContext(ctx, query, log.ID, log.ActorID, log.ActorUsername, log.Action, log.Resource, log.Outcome, log.SourceIP, log.DetailsJSON, log.CreatedAt); err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (s *SQLStore) ListAuditLogs(ctx context.Context, limit int, queryText string) ([]model.AuditLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	query := `SELECT id, actor_id, actor_username, action, resource, outcome, source_ip, details_json, created_at FROM audit_logs`
	args := make([]any, 0)
	if queryText != "" {
		query += ` WHERE actor_username LIKE ? OR action LIKE ? OR resource LIKE ? OR outcome LIKE ? OR source_ip LIKE ?`
		match := "%" + queryText + "%"
		args = append(args, match, match, match, match, match)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]model.AuditLog, 0)
	for rows.Next() {
		var entry model.AuditLog
		if err := rows.Scan(&entry.ID, &entry.ActorID, &entry.ActorUsername, &entry.Action, &entry.Resource, &entry.Outcome, &entry.SourceIP, &entry.DetailsJSON, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit logs: %w", err)
	}
	return logs, nil
}

func (s *SQLStore) CountFailedLoginsSince(ctx context.Context, since time.Time) (int, error) {
	var count int
	query := s.bind(`SELECT COUNT(1) FROM audit_logs WHERE action = ? AND outcome = ? AND created_at >= ?`)
	if err := s.db.QueryRowContext(ctx, query, "auth.login", "deny", since.UTC()).Scan(&count); err != nil {
		return 0, fmt.Errorf("count failed logins: %w", err)
	}
	return count, nil
}

func (s *SQLStore) RecentLoginAudits(ctx context.Context, limit int) ([]model.AuditLog, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`
		SELECT id, actor_id, actor_username, action, resource, outcome, source_ip, details_json, created_at
		FROM audit_logs
		WHERE action = ?
		ORDER BY created_at DESC
		LIMIT ?`), "auth.login", limit)
	if err != nil {
		return nil, fmt.Errorf("list recent login audits: %w", err)
	}
	defer rows.Close()

	logs := make([]model.AuditLog, 0)
	for rows.Next() {
		var entry model.AuditLog
		if err := rows.Scan(&entry.ID, &entry.ActorID, &entry.ActorUsername, &entry.Action, &entry.Resource, &entry.Outcome, &entry.SourceIP, &entry.DetailsJSON, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recent login audit: %w", err)
		}
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent login audits: %w", err)
	}
	return logs, nil
}
