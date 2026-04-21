package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

func (s *Store) CreateSession(ctx context.Context, session domain.Session) error {
	var endedAt any
	if session.EndedAt != nil {
		endedAt = toUnix(*session.EndedAt)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, username, host_id, host_name, source_ip, protocol, status, started_at, ended_at, replay) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.UserID,
		session.Username,
		session.HostID,
		session.HostName,
		session.SourceIP,
		session.Protocol,
		session.Status,
		toUnix(session.StartedAt),
		endedAt,
		session.Replay,
	)
	return err
}

func (s *Store) UpdateSession(ctx context.Context, session domain.Session) error {
	var endedAt any
	if session.EndedAt != nil {
		endedAt = toUnix(*session.EndedAt)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET status = ?, ended_at = ?, replay = ? WHERE id = ?`,
		session.Status,
		endedAt,
		session.Replay,
		session.ID,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrNotFound
	}

	return nil
}

func (s *Store) GetSessionByID(ctx context.Context, id string) (domain.Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, username, host_id, host_name, source_ip, protocol, status, started_at, ended_at, replay FROM sessions WHERE id = ?`, id)
	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Session{}, store.ErrNotFound
		}
		return domain.Session{}, err
	}

	return session, nil
}

func (s *Store) ListSessions(ctx context.Context, filter store.SessionFilter) ([]domain.Session, error) {
	query := strings.Builder{}
	query.WriteString(`SELECT id, user_id, username, host_id, host_name, source_ip, protocol, status, started_at, ended_at, replay FROM sessions WHERE 1=1`)

	args := []any{}
	if filter.Status != "" {
		query.WriteString(` AND status = ?`)
		args = append(args, filter.Status)
	}
	if filter.UserID != "" {
		query.WriteString(` AND user_id = ?`)
		args = append(args, filter.UserID)
	}
	if filter.HostID != "" {
		query.WriteString(` AND host_id = ?`)
		args = append(args, filter.HostID)
	}

	limit := normalizeLimit(filter.Limit)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query.WriteString(` ORDER BY started_at DESC LIMIT ? OFFSET ?`)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]domain.Session, 0, limit)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

func scanSession(scanner interface{ Scan(dest ...any) error }) (domain.Session, error) {
	var session domain.Session
	var startedAt int64
	var endedAt sql.NullInt64

	err := scanner.Scan(
		&session.ID,
		&session.UserID,
		&session.Username,
		&session.HostID,
		&session.HostName,
		&session.SourceIP,
		&session.Protocol,
		&session.Status,
		&startedAt,
		&endedAt,
		&session.Replay,
	)
	if err != nil {
		return domain.Session{}, err
	}

	session.StartedAt = fromUnix(startedAt)
	if endedAt.Valid {
		ended := fromUnix(endedAt.Int64)
		session.EndedAt = &ended
	}

	return session, nil
}
