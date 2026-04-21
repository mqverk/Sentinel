package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

func (s *Store) ListHosts(ctx context.Context) ([]domain.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, address, port, environment, active, created_at, updated_at FROM hosts ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hosts := make([]domain.Host, 0, 32)
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

func (s *Store) GetHostByID(ctx context.Context, id string) (domain.Host, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, address, port, environment, active, created_at, updated_at FROM hosts WHERE id = ?`, id)
	host, err := scanHost(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Host{}, store.ErrNotFound
		}
		return domain.Host{}, err
	}

	return host, nil
}

func (s *Store) GetHostByAddress(ctx context.Context, address string, port int) (domain.Host, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, address, port, environment, active, created_at, updated_at FROM hosts WHERE address = ? AND port = ?`, address, port)
	host, err := scanHost(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Host{}, store.ErrNotFound
		}
		return domain.Host{}, err
	}

	return host, nil
}

func (s *Store) CreateHost(ctx context.Context, host domain.Host) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hosts (id, name, address, port, environment, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		host.ID,
		host.Name,
		host.Address,
		host.Port,
		host.Environment,
		boolToInt(host.Active),
		toUnix(host.CreatedAt),
		toUnix(host.UpdatedAt),
	)
	return err
}

func (s *Store) UpdateHost(ctx context.Context, host domain.Host) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE hosts SET name = ?, address = ?, port = ?, environment = ?, active = ?, updated_at = ? WHERE id = ?`,
		host.Name,
		host.Address,
		host.Port,
		host.Environment,
		boolToInt(host.Active),
		toUnix(host.UpdatedAt),
		host.ID,
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

func scanHost(scanner interface{ Scan(dest ...any) error }) (domain.Host, error) {
	var host domain.Host
	var active int
	var createdAt int64
	var updatedAt int64

	err := scanner.Scan(
		&host.ID,
		&host.Name,
		&host.Address,
		&host.Port,
		&host.Environment,
		&active,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return domain.Host{}, err
	}

	host.Active = active == 1
	host.CreatedAt = fromUnix(createdAt)
	host.UpdatedAt = fromUnix(updatedAt)

	return host, nil
}
