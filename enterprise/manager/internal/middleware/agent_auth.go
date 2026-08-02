package middleware

import (
	"context"
	"net/http"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/crypto"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type ctxKey int

const ctxKeyAgent ctxKey = 1
const ctxKeyUser ctxKey = 2

// AgentAuthenticator resolves agent tokens to identity.
type AgentAuthenticator interface {
	FindAgentByTokenHash(ctx context.Context, tokenHash string) (domain.AgentAuth, error)
}

// AgentAuth validates X-Agent-Token and attaches agent context.
func AgentAuth(auth AgentAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Agent-Token")
			if token == "" {
				writeError(w, http.StatusUnauthorized, "MISSING_TOKEN", "X-Agent-Token header required")
				return
			}
			agent, err := auth.FindAgentByTokenHash(r.Context(), crypto.HashToken(token))
			if err != nil {
				writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid agent token")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyAgent, agent)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AgentFromContext returns authenticated agent metadata.
func AgentFromContext(ctx context.Context) (domain.AgentAuth, bool) {
	v, ok := ctx.Value(ctxKeyAgent).(domain.AgentAuth)
	return v, ok
}

// JWTAuthStub is deprecated — use JWTAuth in jwt_auth.go.
func JWTAuthStubLegacy(next http.Handler) http.Handler {
	return next
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = jsonEncode(w, models.ErrorResponse{Error: models.APIError{Code: code, Message: msg}})
}
