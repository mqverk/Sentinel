package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinel/backend/internal/api/middleware"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

type createHostRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Environment string `json:"environment"`
	Active      *bool  `json:"active,omitempty"`
}

type updateHostRequest struct {
	Name        *string `json:"name,omitempty"`
	Address     *string `json:"address,omitempty"`
	Port        *int    `json:"port,omitempty"`
	Environment *string `json:"environment,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req createHostRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Address = strings.TrimSpace(req.Address)
	req.Environment = strings.TrimSpace(req.Environment)
	if req.Name == "" || req.Address == "" || req.Environment == "" || req.Port <= 0 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "name, address, environment, and valid port are required")
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	now := time.Now().UTC()
	host := domain.Host{
		ID:          uuid.NewString(),
		Name:        req.Name,
		Address:     req.Address,
		Port:        req.Port,
		Environment: req.Environment,
		Active:      active,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.store.CreateHost(r.Context(), host); err != nil {
		writeError(w, http.StatusConflict, "failed to create host")
		return
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"host.create",
		host.Name,
		"success",
		requestIP(r),
		map[string]any{"hostId": host.ID},
	))

	writeJSON(w, http.StatusCreated, map[string]any{"host": host})
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	hostID := strings.TrimSpace(chi.URLParam(r, "hostID"))
	if hostID == "" {
		writeError(w, http.StatusBadRequest, "hostID is required")
		return
	}

	host, err := s.store.GetHostByID(r.Context(), hostID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to load host")
		return
	}

	var req updateHostRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.Name != nil {
		host.Name = strings.TrimSpace(*req.Name)
	}
	if req.Address != nil {
		host.Address = strings.TrimSpace(*req.Address)
	}
	if req.Port != nil {
		host.Port = *req.Port
	}
	if req.Environment != nil {
		host.Environment = strings.TrimSpace(*req.Environment)
	}
	if req.Active != nil {
		host.Active = *req.Active
	}

	if host.Name == "" || host.Address == "" || host.Environment == "" || host.Port <= 0 || host.Port > 65535 {
		writeError(w, http.StatusBadRequest, "host fields are invalid")
		return
	}

	host.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateHost(r.Context(), host); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update host")
		return
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"host.update",
		host.Name,
		"success",
		requestIP(r),
		map[string]any{"hostId": host.ID},
	))

	writeJSON(w, http.StatusOK, map[string]any{"host": host})
}
