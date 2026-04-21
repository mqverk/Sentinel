package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"sentinel/backend/internal/model"
)

func (s *SQLStore) AuthenticateUser(ctx context.Context, username string) (*model.User, error) {
	query := s.bind(`SELECT id, username, email, password_hash, disabled, created_at, last_login_at FROM users WHERE username = ?`)
	row := s.db.QueryRowContext(ctx, query, username)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query user by username: %w", err)
	}
	return user, nil
}

func (s *SQLStore) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
	query := s.bind(`SELECT id, username, email, password_hash, disabled, created_at, last_login_at FROM users WHERE id = ?`)
	row := s.db.QueryRowContext(ctx, query, userID)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query user by id: %w", err)
	}
	return user, nil
}

func (s *SQLStore) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, email, password_hash, disabled, created_at, last_login_at FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]model.User, 0)
	for rows.Next() {
		var user model.User
		var lastLogin sql.NullTime
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Disabled, &user.CreatedAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if lastLogin.Valid {
			at := lastLogin.Time
			user.LastLoginAt = &at
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

func (s *SQLStore) CreateUser(ctx context.Context, user model.User) error {
	query := s.bind(`INSERT INTO users (id, username, email, password_hash, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
	if _, err := s.db.ExecContext(ctx, query, user.ID, user.Username, user.Email, user.PasswordHash, user.Disabled, user.CreatedAt); err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *SQLStore) ReplaceUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin replace user roles transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM user_roles WHERE user_id = ?`), userID); err != nil {
		return fmt.Errorf("clear user roles: %w", err)
	}
	for _, roleID := range roleIDs {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`), userID, roleID); err != nil {
			return fmt.Errorf("insert user role: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace user roles: %w", err)
	}
	return nil
}

func (s *SQLStore) UpdateLastLogin(ctx context.Context, userID string, loginAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE users SET last_login_at = ? WHERE id = ?`), loginAt.UTC(), userID); err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

func (s *SQLStore) ListRoles(ctx context.Context) ([]model.Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, created_at FROM roles ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	roles := make([]model.Role, 0)
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}
	return roles, nil
}

func (s *SQLStore) CreateRole(ctx context.Context, role model.Role) error {
	query := s.bind(`INSERT INTO roles (id, name, description, created_at) VALUES (?, ?, ?, ?)`)
	if _, err := s.db.ExecContext(ctx, query, role.ID, role.Name, role.Description, role.CreatedAt); err != nil {
		return fmt.Errorf("insert role: %w", err)
	}
	return nil
}

func (s *SQLStore) ListPermissions(ctx context.Context) ([]model.Permission, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, resource, action, description, created_at FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]model.Permission, 0)
	for rows.Next() {
		var permission model.Permission
		if err := rows.Scan(&permission.ID, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}
	return permissions, nil
}

func (s *SQLStore) ListRolePermissions(ctx context.Context, roleID string) ([]model.Permission, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`
		SELECT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = ?
		ORDER BY p.resource, p.action`), roleID)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]model.Permission, 0)
	for rows.Next() {
		var permission model.Permission
		if err := rows.Scan(&permission.ID, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role permission: %w", err)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role permissions: %w", err)
	}
	return permissions, nil
}

func (s *SQLStore) ReplaceRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin replace role permissions transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.replaceRolePermissionsTx(ctx, tx, roleID, permissionIDs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace role permissions: %w", err)
	}
	return nil
}

func (s *SQLStore) replaceRolePermissionsTx(ctx context.Context, tx *sql.Tx, roleID string, permissionIDs []string) error {
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM role_permissions WHERE role_id = ?`), roleID); err != nil {
		return fmt.Errorf("clear role permissions: %w", err)
	}
	for _, permissionID := range permissionIDs {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`), roleID, permissionID); err != nil {
			return fmt.Errorf("insert role permission: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) UserRoles(ctx context.Context, userID string) ([]model.Role, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`
		SELECT r.id, r.name, r.description, r.created_at
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.name ASC`), userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()

	roles := make([]model.Role, 0)
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user roles: %w", err)
	}
	return roles, nil
}

func (s *SQLStore) UserPermissions(ctx context.Context, userID string) ([]model.Permission, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`
		SELECT DISTINCT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = ?
		ORDER BY p.resource, p.action`), userID)
	if err != nil {
		return nil, fmt.Errorf("list user permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]model.Permission, 0)
	for rows.Next() {
		var permission model.Permission
		if err := rows.Scan(&permission.ID, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user permission: %w", err)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user permissions: %w", err)
	}
	return permissions, nil
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (*model.User, error) {
	var user model.User
	var lastLogin sql.NullTime
	if err := scanner.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Disabled, &user.CreatedAt, &lastLogin); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		at := lastLogin.Time
		user.LastLoginAt = &at
	}
	return &user, nil
}
