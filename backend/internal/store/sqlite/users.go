package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

func (s *Store) ListUsers(ctx context.Context, search string) ([]domain.User, error) {
	query := `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users`
	args := []any{}

	if search != "" {
		query += ` WHERE lower(username) LIKE ? OR lower(display_name) LIKE ?`
		like := "%" + strings.ToLower(search) + "%"
		args = append(args, like, like)
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]domain.User, 0, 32)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users WHERE username = ?`, username)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, store.ErrNotFound
		}
		return domain.User{}, err
	}

	return user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users WHERE id = ?`, id)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, store.ErrNotFound
		}
		return domain.User{}, err
	}

	return user, nil
}

func (s *Store) CreateUser(ctx context.Context, user domain.User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, display_name, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID,
		user.Username,
		user.PasswordHash,
		user.DisplayName,
		boolToInt(user.Disabled),
		toUnix(user.CreatedAt),
		toUnix(user.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (s *Store) UpdateUser(ctx context.Context, user domain.User) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, display_name = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		user.PasswordHash,
		user.DisplayName,
		boolToInt(user.Disabled),
		toUnix(user.UpdatedAt),
		user.ID,
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

func (s *Store) ListUserRoles(ctx context.Context, userID string) ([]domain.Role, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.name ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]domain.Role, 0, 8)
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}

		permissions, err := s.rolePermissions(ctx, s.db, role.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = permissions

		roles = append(roles, role)
	}

	return roles, rows.Err()
}

func (s *Store) SetUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}

	for _, roleID := range roleIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, roleID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (domain.User, error) {
	var user domain.User
	var disabled int
	var createdAt int64
	var updatedAt int64

	err := scanner.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.DisplayName,
		&disabled,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return domain.User{}, err
	}

	user.Disabled = disabled == 1
	user.CreatedAt = fromUnix(createdAt)
	user.UpdatedAt = fromUnix(updatedAt)

	return user, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}

func nowUTC() time.Time {
	return time.Now().UTC()
}
