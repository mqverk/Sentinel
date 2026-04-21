package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"sentinel/backend/internal/api/middleware"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/store"
)

type startSessionRequest struct {
	HostID string `json:"hostId"`
}

type endSessionRequest struct {
	Status string `json:"status"`
	Replay string `json:"replay"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	filter := store.SessionFilter{
		Status: strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:  queryInt(r, "limit", 100),
		Offset: queryInt(r, "offset", 0),
	}

	sessions, err := s.sessions.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing auth context")
		return
	}

	roles, ok := rolesFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "missing role context")
		return
	}

	var req startSessionRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.HostID = strings.TrimSpace(req.HostID)
	if req.HostID == "" {
		writeError(w, http.StatusBadRequest, "hostId is required")
		return
	}

	host, err := s.store.GetHostByID(r.Context(), req.HostID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to load host")
		return
	}

	if !s.policy.CanAccessHost(roles, host) {
		_ = s.audit.Record(r.Context(), audit.NewEntry(
			claims.UserID,
			claims.Username,
			"session.start",
			host.Name,
			"denied",
			requestIP(r),
			map[string]any{"hostId": host.ID},
		))
		writeError(w, http.StatusForbidden, "host access denied")
		return
	}

	sessionEntry, err := s.sessions.Start(r.Context(), session.StartInput{
		UserID:   claims.UserID,
		Username: claims.Username,
		HostID:   host.ID,
		HostName: host.Name,
		SourceIP: requestIP(r),
		Protocol: domain.SessionProtocolSSHTunnel,
		Status:   domain.SessionStatusActive,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start session")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"session": sessionEntry})
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "sessionID"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionID is required")
		return
	}

	var req endSessionRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.Status == "" {
		req.Status = domain.SessionStatusClosed
	}

	if err := s.sessions.End(r.Context(), sessionID, req.Status, req.Replay); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to end session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ended"})
}

func (s *Server) handleSessionReplay(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(chi.URLParam(r, "sessionID"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionID is required")
		return
	}

	sessionEntry, err := s.sessions.GetByID(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to load session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId": sessionEntry.ID,
		"status":    sessionEntry.Status,
		"replay":    sessionEntry.Replay,
	})
}
