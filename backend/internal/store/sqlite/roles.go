package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

func (s *Store) ListRoles(ctx context.Context, search string) ([]domain.Role, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM roles`
	args := []any{}

	if search != "" {
		query += ` WHERE lower(name) LIKE ? OR lower(description) LIKE ?`
		like := "%" + strings.ToLower(search) + "%"
		args = append(args, like, like)
	}

	query += ` ORDER BY name ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]domain.Role, 0, 16)
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

func (s *Store) GetRoleByID(ctx context.Context, id string) (domain.Role, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM roles WHERE id = ?`, id)
	role, err := scanRole(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Role{}, store.ErrNotFound
		}
		return domain.Role{}, err
	}

	permissions, err := s.rolePermissions(ctx, s.db, role.ID)
	if err != nil {
		return domain.Role{}, err
	}
	role.Permissions = permissions

	return role, nil
}

func (s *Store) CreateRole(ctx context.Context, role domain.Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		role.ID,
		role.Name,
		role.Description,
		toUnix(role.CreatedAt),
		toUnix(role.UpdatedAt),
	); err != nil {
		return err
	}

	if err := s.replaceRolePermissions(ctx, tx, role.ID, role.Permissions); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) UpdateRole(ctx context.Context, role domain.Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		role.Name,
		role.Description,
		toUnix(role.UpdatedAt),
		role.ID,
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

	if err := s.replaceRolePermissions(ctx, tx, role.ID, role.Permissions); err != nil {
		return err
	}

	return tx.Commit()
}

func scanRole(scanner interface{ Scan(dest ...any) error }) (domain.Role, error) {
	var role domain.Role
	var createdAt int64
	var updatedAt int64

	err := scanner.Scan(&role.ID, &role.Name, &role.Description, &createdAt, &updatedAt)
	if err != nil {
		return domain.Role{}, err
	}

	role.CreatedAt = fromUnix(createdAt)
	role.UpdatedAt = fromUnix(updatedAt)

	return role, nil
}
