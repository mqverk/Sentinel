package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *SQLStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT value_json FROM settings WHERE key = ?`), key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("query setting: %w", err)
	}
	return value, nil
}

func (s *SQLStore) UpsertSetting(ctx context.Context, key, value string) error {
	now := time.Now().UTC()
	if s.driver == "postgres" {
		_, err := s.db.ExecContext(ctx, s.bind(`
			INSERT INTO settings (key, value_json, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = EXCLUDED.updated_at`), key, value, now)
		if err != nil {
			return fmt.Errorf("upsert setting postgres: %w", err)
		}
		return nil
	}

	_, err := s.db.ExecContext(ctx, s.bind(`
		INSERT INTO settings (key, value_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`), key, value, now)
	if err != nil {
		return fmt.Errorf("upsert setting sqlite: %w", err)
	}
	return nil
}
