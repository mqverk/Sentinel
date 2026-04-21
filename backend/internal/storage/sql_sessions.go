package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"sentinel/backend/internal/model"
)

func (s *SQLStore) CreateSession(ctx context.Context, session model.Session) error {
	query := s.bind(`INSERT INTO sessions (id, user_id, host_id, status, started_at, ended_at, recording_path, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := s.db.ExecContext(ctx, query, session.ID, session.UserID, session.HostID, session.Status, session.StartedAt, session.EndedAt, session.RecordingPath, session.MetadataJSON); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (s *SQLStore) ListSessions(ctx context.Context, status string) ([]model.Session, error) {
	query := `SELECT id, user_id, host_id, status, started_at, ended_at, recording_path, metadata_json FROM sessions`
	args := make([]any, 0)
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY started_at DESC`

	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := make([]model.Session, 0)
	for rows.Next() {
		var session model.Session
		var endedAt sql.NullTime
		if err := rows.Scan(&session.ID, &session.UserID, &session.HostID, &session.Status, &session.StartedAt, &endedAt, &session.RecordingPath, &session.MetadataJSON); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		if endedAt.Valid {
			at := endedAt.Time
			session.EndedAt = &at
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

func (s *SQLStore) GetSession(ctx context.Context, sessionID string) (*model.Session, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, user_id, host_id, status, started_at, ended_at, recording_path, metadata_json FROM sessions WHERE id = ?`), sessionID)
	var session model.Session
	var endedAt sql.NullTime
	if err := row.Scan(&session.ID, &session.UserID, &session.HostID, &session.Status, &session.StartedAt, &endedAt, &session.RecordingPath, &session.MetadataJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query session: %w", err)
	}
	if endedAt.Valid {
		at := endedAt.Time
		session.EndedAt = &at
	}
	return &session, nil
}

func (s *SQLStore) UpdateSessionStatus(ctx context.Context, sessionID, status string, endedAt *time.Time) error {
	if endedAt == nil {
		if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE sessions SET status = ? WHERE id = ?`), status, sessionID); err != nil {
			return fmt.Errorf("update session status: %w", err)
		}
		return nil
	}

	if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE sessions SET status = ?, ended_at = ? WHERE id = ?`), status, endedAt.UTC(), sessionID); err != nil {
		return fmt.Errorf("update session status with end time: %w", err)
	}
	return nil
}
