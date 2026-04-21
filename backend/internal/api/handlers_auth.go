package api

import (
	"net/http"

	"sentinel/backend/internal/audit"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := s.authService.Login(r.Context(), request.Username, request.Password)
	if err != nil {
		s.auditService.Log(r.Context(), audit.Event{
			ActorID:       "anonymous",
			ActorUsername: request.Username,
			Action:        "auth.login",
			Resource:      "auth",
			Outcome:       "deny",
			SourceIP:      sourceIP(r),
			Details: map[string]any{
				"reason": err.Error(),
			},
		})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       result.Principal.UserID,
		ActorUsername: result.Principal.Username,
		Action:        "auth.login",
		Resource:      "auth",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"roles": result.Principal.Roles,
		},
	})

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}
	writeJSON(w, http.StatusOK, principal)
}
