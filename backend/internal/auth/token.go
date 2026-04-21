package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Principal struct {
	UserID        string   `json:"userId"`
	Username      string   `json:"username"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	Authenticated bool     `json:"authenticated"`
}

type contextKey string

const principalContextKey contextKey = "principal"

type Claims struct {
	Principal Principal `json:"principal"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	return &TokenManager{secret: []byte(secret), ttl: ttl}
}

func (m *TokenManager) Generate(principal Principal) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(m.ttl)
	claims := Claims{
		Principal: principal,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Subject:   principal.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return signed, expiresAt, nil
}

func (m *TokenManager) Parse(tokenString string) (Principal, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return Principal{}, fmt.Errorf("parse jwt: %w", err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return Principal{}, errors.New("invalid token claims")
	}

	principal := claims.Principal
	principal.Authenticated = true
	return principal, nil
}

func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(Principal)
	return principal, ok
}
