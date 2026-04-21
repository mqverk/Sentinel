package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

func (s *Store) CreateAuditLog(ctx context.Context, logEntry domain.AuditLog) error {
	metadata := "{}"
	if len(logEntry.Metadata) > 0 {
		encoded, err := json.Marshal(logEntry.Metadata)
		if err != nil {
			return err
		}
		metadata = string(encoded)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (timestamp, actor_id, actor_username, action, resource, result, source_ip, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		toUnix(logEntry.Timestamp),
		logEntry.ActorID,
		logEntry.ActorUsername,
		logEntry.Action,
		logEntry.Resource,
		logEntry.Result,
		logEntry.SourceIP,
		metadata,
	)
	return err
}

func (s *Store) ListAuditLogs(ctx context.Context, filter store.AuditFilter) ([]domain.AuditLog, error) {
	query := strings.Builder{}
	query.WriteString(`SELECT id, timestamp, actor_id, actor_username, action, resource, result, source_ip, metadata FROM audit_logs WHERE 1=1`)

	args := []any{}
	if filter.Search != "" {
		like := "%" + strings.ToLower(filter.Search) + "%"
		query.WriteString(` AND (lower(actor_username) LIKE ? OR lower(action) LIKE ? OR lower(resource) LIKE ?)`)
		args = append(args, like, like, like)
	}
	if filter.Action != "" {
		query.WriteString(` AND action = ?`)
		args = append(args, filter.Action)
	}
	if filter.Result != "" {
		query.WriteString(` AND result = ?`)
		args = append(args, filter.Result)
	}

	limit := normalizeLimit(filter.Limit)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query.WriteString(` ORDER BY timestamp DESC LIMIT ? OFFSET ?`)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]domain.AuditLog, 0, limit)
	for rows.Next() {
		entry, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}

	return logs, rows.Err()
}

func scanAudit(scanner interface{ Scan(dest ...any) error }) (domain.AuditLog, error) {
	var entry domain.AuditLog
	var timestamp int64
	var metadataRaw string

	err := scanner.Scan(
		&entry.ID,
		&timestamp,
		&entry.ActorID,
		&entry.ActorUsername,
		&entry.Action,
		&entry.Resource,
		&entry.Result,
		&entry.SourceIP,
		&metadataRaw,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AuditLog{}, store.ErrNotFound
		}
		return domain.AuditLog{}, err
	}

	entry.Timestamp = fromUnix(timestamp)
	if metadataRaw != "" {
		metadata := make(map[string]any)
		if err := json.Unmarshal([]byte(metadataRaw), &metadata); err == nil {
			entry.Metadata = metadata
		}
	}

	return entry, nil
}
