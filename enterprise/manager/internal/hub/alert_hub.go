package hub

import (
	"encoding/json"
	"sync"

	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// AlertHub broadcasts new alerts to SOC dashboard WebSocket clients.
type AlertHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

func NewAlertHub() *AlertHub {
	return &AlertHub{clients: map[chan []byte]struct{}{}}
}

func (h *AlertHub) Subscribe() chan []byte {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *AlertHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *AlertHub) Publish(alert models.AlertSummary) {
	data, err := json.Marshal(alert)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
		}
	}
}
