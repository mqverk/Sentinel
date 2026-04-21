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
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/store"
)

type createUserRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	DisplayName string   `json:"displayName"`
	Disabled    bool     `json:"disabled"`
	RoleIDs     []string `json:"roleIds"`
}

type updateUserRequest struct {
	Password    *string   `json:"password,omitempty"`
	DisplayName *string   `json:"displayName,omitempty"`
	Disabled    *bool     `json:"disabled,omitempty"`
	RoleIDs     *[]string `json:"roleIds,omitempty"`
}

type createRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type updateRoleRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	users, err := s.store.ListUsers(r.Context(), search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	response := make([]domain.UserSafe, 0, len(users))
	for _, user := range users {
		roles, err := s.store.ListUserRoles(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to resolve user roles")
			return
		}

		safe := user.Safe()
		safe.Roles = roles
		response = append(response, safe)
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": response})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" || req.DisplayName == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, "username, password, and displayName are required")
		return
	}

	if err := s.auth.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	now := time.Now().UTC()
	user := domain.User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		PasswordHash: hashed,
		DisplayName:  req.DisplayName,
		Disabled:     req.Disabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusConflict, "failed to create user")
		return
	}

	if len(req.RoleIDs) > 0 {
		if err := s.store.SetUserRoles(r.Context(), user.ID, req.RoleIDs); err != nil {
			writeError(w, http.StatusBadRequest, "failed to assign roles")
			return
		}
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"user.create",
		user.Username,
		"success",
		requestIP(r),
		map[string]any{"userId": user.ID},
	))

	roles, _ := s.store.ListUserRoles(r.Context(), user.ID)
	safe := user.Safe()
	safe.Roles = roles

	writeJSON(w, http.StatusCreated, map[string]any{"user": safe})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID is required")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	var req updateUserRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if req.Disabled != nil {
		user.Disabled = *req.Disabled
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		if err := s.auth.ValidatePassword(*req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		hashed, err := auth.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		user.PasswordHash = hashed
	}

	user.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	if req.RoleIDs != nil {
		if err := s.store.SetUserRoles(r.Context(), user.ID, *req.RoleIDs); err != nil {
			writeError(w, http.StatusBadRequest, "failed to update role assignments")
			return
		}
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"user.update",
		user.Username,
		"success",
		requestIP(r),
		map[string]any{"userId": user.ID},
	))

	roles, _ := s.store.ListUserRoles(r.Context(), user.ID)
	safe := user.Safe()
	safe.Roles = roles

	writeJSON(w, http.StatusOK, map[string]any{"user": safe})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	roles, err := s.store.ListRoles(r.Context(), search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req createRoleRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" || req.Description == "" {
		writeError(w, http.StatusBadRequest, "name and description are required")
		return
	}

	permissions, ok := sanitizePermissions(req.Permissions)
	if !ok {
		writeError(w, http.StatusBadRequest, "one or more permissions are invalid")
		return
	}

	now := time.Now().UTC()
	role := domain.Role{
		ID:          uuid.NewString(),
		Name:        req.Name,
		Description: req.Description,
		Permissions: permissions,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.store.CreateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusConflict, "failed to create role")
		return
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"role.create",
		role.Name,
		"success",
		requestIP(r),
		map[string]any{"roleId": role.ID},
	))

	writeJSON(w, http.StatusCreated, map[string]any{"role": role})
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(chi.URLParam(r, "roleID"))
	if roleID == "" {
		writeError(w, http.StatusBadRequest, "roleID is required")
		return
	}

	role, err := s.store.GetRoleByID(r.Context(), roleID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "role not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to load role")
		return
	}

	var req updateRoleRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.Name != nil {
		role.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		role.Description = strings.TrimSpace(*req.Description)
	}
	if req.Permissions != nil {
		permissions, ok := sanitizePermissions(*req.Permissions)
		if !ok {
			writeError(w, http.StatusBadRequest, "one or more permissions are invalid")
			return
		}
		role.Permissions = permissions
	}

	role.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update role")
		return
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"role.update",
		role.Name,
		"success",
		requestIP(r),
		map[string]any{"roleId": role.ID},
	))

	writeJSON(w, http.StatusOK, map[string]any{"role": role})
}

func (s *Server) handleListPermissions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"permissions": policy.PermissionsCatalog})
}

func sanitizePermissions(input []string) ([]string, bool) {
	if len(input) == 0 {
		return []string{}, true
	}

	known := map[string]struct{}{}
	for _, permission := range policy.PermissionsCatalog {
		known[permission] = struct{}{}
	}

	result := make([]string, 0, len(input))
	seen := map[string]struct{}{}
	for _, permission := range input {
		normalized := strings.TrimSpace(permission)
		if normalized == "" {
			continue
		}

		if normalized != "*" {
			if _, ok := known[normalized]; !ok && !strings.HasSuffix(normalized, ":*") {
				return nil, false
			}
		}

		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}

	return result, true
}
