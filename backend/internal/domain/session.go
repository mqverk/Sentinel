package domain

import "time"

const (
	SessionStatusActive      = "active"
	SessionStatusClosed      = "closed"
	SessionStatusDenied      = "denied"
	SessionStatusFailed      = "failed"
	SessionProtocolSSHShell  = "ssh-shell"
	SessionProtocolSSHTunnel = "ssh-tunnel"
)

type Session struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	Username  string     `json:"username"`
	HostID    string     `json:"hostId"`
	HostName  string     `json:"hostName"`
	SourceIP  string     `json:"sourceIp"`
	Protocol  string     `json:"protocol"`
	Status    string     `json:"status"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
	Replay    string     `json:"replay,omitempty"`
}
