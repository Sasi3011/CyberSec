package middleware

import (
	"context"
	"net/http"
	"strings"

	jwtpkg "github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/jwt"
)

type UserContext struct {
	UserID         string
	OrganizationID string
	Role           string
	Email          string
}

// JWTAuth validates Bearer tokens for SOC/admin routes.
func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "MISSING_TOKEN", "Bearer token required")
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			claims, err := jwtpkg.ParseAccess(secret, token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, UserContext{
				UserID:         claims.UserID,
				OrganizationID: claims.OrganizationID,
				Role:           claims.Role,
				Email:          claims.Email,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) (UserContext, bool) {
	v, ok := ctx.Value(ctxKeyUser).(UserContext)
	return v, ok
}

// RequireRole blocks requests when role is insufficient.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
				return
			}
			if user.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := allowed[user.Role]; !ok {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReadOnly blocks mutating methods for auditor role.
func ReadOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if ok && user.Role == "auditor" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusForbidden, "READ_ONLY", "auditor role is read-only")
			return
		}
		next.ServeHTTP(w, r)
	})
}
