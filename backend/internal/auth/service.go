package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sentinel/backend/internal/model"
	"sentinel/backend/internal/storage"
)

type Service struct {
	store             storage.Store
	tokenManager      *TokenManager
	passwordMinLength int
}

type LoginResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Principal Principal `json:"principal"`
}

func NewService(store storage.Store, tokenManager *TokenManager, passwordMinLength int) *Service {
	return &Service{
		store:             store,
		tokenManager:      tokenManager,
		passwordMinLength: passwordMinLength,
	}
}

func (s *Service) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	user, err := s.store.AuthenticateUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("authenticate user: %w", err)
	}
	if user.Disabled {
		return nil, fmt.Errorf("user is disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	principal, err := s.principalFromUser(ctx, *user)
	if err != nil {
		return nil, err
	}

	token, expiresAt, err := s.tokenManager.Generate(principal)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	if err := s.store.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("update last login: %w", err)
	}

	return &LoginResult{Token: token, ExpiresAt: expiresAt, Principal: principal}, nil
}

func (s *Service) VerifyToken(token string) (Principal, error) {
	return s.tokenManager.Parse(token)
}

func (s *Service) AuthenticatePassword(ctx context.Context, username, password string) (Principal, error) {
	user, err := s.store.AuthenticateUser(ctx, username)
	if err != nil {
		return Principal{}, fmt.Errorf("authenticate user: %w", err)
	}
	if user.Disabled {
		return Principal{}, fmt.Errorf("user is disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return Principal{}, fmt.Errorf("invalid credentials")
	}
	return s.principalFromUser(ctx, *user)
}

func (s *Service) principalFromUser(ctx context.Context, user model.User) (Principal, error) {
	roles, err := s.store.UserRoles(ctx, user.ID)
	if err != nil {
		return Principal{}, fmt.Errorf("fetch user roles: %w", err)
	}
	permissions, err := s.store.UserPermissions(ctx, user.ID)
	if err != nil {
		return Principal{}, fmt.Errorf("fetch user permissions: %w", err)
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	permissionNames := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permissionNames = append(permissionNames, permission.Resource+":"+permission.Action)
	}

	return Principal{
		UserID:        user.ID,
		Username:      user.Username,
		Roles:         roleNames,
		Permissions:   permissionNames,
		Authenticated: true,
	}, nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func (s *Service) ValidatePassword(password string) error {
	if len(strings.TrimSpace(password)) < s.passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", s.passwordMinLength)
	}
	return nil
}
