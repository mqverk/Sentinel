package api

import (
	"net/http"
	"time"

	"sentinel/backend/internal/model"
)

func (s *Server) handleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	active, err := s.store.ListSessions(r.Context(), "active")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list active sessions")
		return
	}
	recentLogins, err := s.store.RecentLoginAudits(r.Context(), 8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load recent logins")
		return
	}
	failedLastDay, err := s.store.CountFailedLoginsSince(r.Context(), time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count alerts")
		return
	}

	overview := model.DashboardOverview{
		ActiveSessions: len(active),
		RecentLogins:   recentLogins,
		OpenAlerts:     failedLastDay,
	}
	writeJSON(w, http.StatusOK, overview)
}
