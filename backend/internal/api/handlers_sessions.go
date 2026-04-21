package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"sentinel/backend/internal/audit"
)

type startSessionRequest struct {
	HostID   string         `json:"hostId"`
	Metadata map[string]any `json:"metadata"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	sessions, err := s.sessionService.ListSessions(r.Context(), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	var request startSessionRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.HostID) == "" {
		writeError(w, http.StatusBadRequest, "hostId is required")
		return
	}

	decision, err := s.policyEngine.CanConnect(r.Context(), principal, request.HostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to evaluate host policy")
		return
	}
	if !decision.Allowed {
		s.auditService.Log(r.Context(), audit.Event{
			ActorID:       principal.UserID,
			ActorUsername: principal.Username,
			Action:        "sessions.start",
			Resource:      "sessions",
			Outcome:       "deny",
			SourceIP:      sourceIP(r),
			Details: map[string]any{
				"hostID": request.HostID,
				"reason": decision.Reason,
			},
		})
		writeError(w, http.StatusForbidden, decision.Reason)
		return
	}

	metadata, err := json.Marshal(request.Metadata)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	sessionEntry, err := s.sessionService.StartSession(r.Context(), principal.UserID, request.HostID, string(metadata))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start session")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "sessions.start",
		Resource:      "sessions",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"sessionID": sessionEntry.ID,
			"hostID":    request.HostID,
		},
	})

	writeJSON(w, http.StatusCreated, sessionEntry)
}

func (s *Server) handleReplaySession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if strings.TrimSpace(sessionID) == "" {
		writeError(w, http.StatusBadRequest, "sessionID is required")
		return
	}

	frames, err := s.sessionService.Replay(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session replay unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessionId": sessionID, "frames": frames})
}

func (s *Server) handleTerminateSession(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	sessionID := chi.URLParam(r, "sessionID")
	if strings.TrimSpace(sessionID) == "" {
		writeError(w, http.StatusBadRequest, "sessionID is required")
		return
	}

	if err := s.sessionService.EndSession(r.Context(), sessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to terminate session")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "sessions.terminate",
		Resource:      "sessions",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"sessionID": sessionID,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "terminated"})
}
