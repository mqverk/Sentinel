package middleware

import (
	"context"
	"net/http"
	"strings"

	"sentinel/backend/internal/auth"
)

type claimsContextKey struct{}

func Authenticate(tokens *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}

			rawToken := strings.TrimSpace(authorization[7:])
			claims, err := tokens.ParseToken(rawToken)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*auth.Claims)
	if !ok {
		return nil, false
	}

	return claims, true
}
