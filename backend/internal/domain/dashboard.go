package domain

type DashboardSummary struct {
	ActiveSessions int64 `json:"activeSessions"`
	RecentLogins   int64 `json:"recentLogins"`
	Alerts         int64 `json:"alerts"`
}
