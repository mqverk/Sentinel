package sqlite

import (
	"context"
	"time"

	"sentinel/backend/internal/domain"
)

func (s *Store) GetDashboardSummary(ctx context.Context) (domain.DashboardSummary, error) {
	summary := domain.DashboardSummary{}

	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE status = ?`, domain.SessionStatusActive).Scan(&summary.ActiveSessions)
	if err != nil {
		return domain.DashboardSummary{}, err
	}

	recentCutoff := time.Now().UTC().Add(-24 * time.Hour).Unix()
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login' AND result = 'success' AND timestamp >= ?`,
		recentCutoff,
	).Scan(&summary.RecentLogins)
	if err != nil {
		return domain.DashboardSummary{}, err
	}

	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE result = 'denied' AND timestamp >= ?`,
		recentCutoff,
	).Scan(&summary.Alerts)
	if err != nil {
		return domain.DashboardSummary{}, err
	}

	return summary, nil
}
