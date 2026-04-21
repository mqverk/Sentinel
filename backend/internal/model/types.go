package model

import "time"

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
}

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Permission struct {
	ID          string    `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Host struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Environment string    `json:"environment"`
	Criticality string    `json:"criticality"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Policy struct {
	ID         string    `json:"id"`
	RoleID     string    `json:"roleId"`
	HostID     string    `json:"hostId"`
	CanConnect bool      `json:"canConnect"`
	RequireMFA bool      `json:"requireMfa"`
	CreatedAt  time.Time `json:"createdAt"`
}

type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"userId"`
	HostID        string     `json:"hostId"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"startedAt"`
	EndedAt       *time.Time `json:"endedAt,omitempty"`
	RecordingPath string     `json:"recordingPath"`
	MetadataJSON  string     `json:"metadataJson"`
}

type ReplayFrame struct {
	OffsetMillis int64  `json:"offsetMillis"`
	Stream       string `json:"stream"`
	Payload      string `json:"payload"`
}

type AuditLog struct {
	ID            string    `json:"id"`
	ActorID       string    `json:"actorId"`
	ActorUsername string    `json:"actorUsername"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource"`
	Outcome       string    `json:"outcome"`
	SourceIP      string    `json:"sourceIp"`
	DetailsJSON   string    `json:"detailsJson"`
	CreatedAt     time.Time `json:"createdAt"`
}

type DashboardOverview struct {
	ActiveSessions int        `json:"activeSessions"`
	RecentLogins   []AuditLog `json:"recentLogins"`
	OpenAlerts     int        `json:"openAlerts"`
}
