package handler

import (
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/hub"
	jwtpkg "github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/jwt"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func AlertsWebSocket(jwtSecret string, alertHub *hub.AlertHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "MISSING_TOKEN", "token query param required")
			return
		}
		if _, err := jwtpkg.ParseAccess(jwtSecret, token); err != nil {
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid token")
			return
		}
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ch := alertHub.Subscribe()
		defer alertHub.Unsubscribe(ch)
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for msg := range ch {
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}
}
