package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/middleware"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type API struct {
	Agents    *service.AgentService
	Alerts    *service.AlertService
	Decisions *service.DecisionService
	IOCs      *service.IOCService
	Endpoints *service.EndpointService
	OverviewSvc *service.OverviewService
}

func (h *API) Register(w http.ResponseWriter, r *http.Request) {
	var req models.AgentRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	resp, err := h.Agents.Register(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "REGISTER_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *API) Heartbeat(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	var req models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	resp, err := h.Agents.Heartbeat(r.Context(), auth, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "HEARTBEAT_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *API) UploadAlerts(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	var req models.AlertsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	req.AgentID = auth.AgentID
	resp, err := h.Alerts.Upload(r.Context(), auth, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ALERT_UPLOAD_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *API) UploadDecisions(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	var req models.DecisionsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	req.AgentID = auth.AgentID
	resp, err := h.Decisions.Upload(r.Context(), auth, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DECISION_UPLOAD_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *API) ListIOCs(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since_version"), 10, 64)
	resp, err := h.IOCs.ListSince(r.Context(), auth, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "IOC_LIST_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *API) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	agents, err := h.Endpoints.ListForOrg(r.Context(), auth.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ENDPOINTS_FAILED", err.Error())
		return
	}
	out := make([]models.EndpointSummary, 0, len(agents))
	for _, a := range agents {
		out = append(out, models.EndpointSummary{
			ID: a.ID, Hostname: a.Hostname, Status: a.Status,
			PublicIP: a.PublicIP, LocalIP: a.LocalIP,
			AgentVersion: a.AgentVersion, Health: a.Health,
			EngineStatus: a.EngineStatus, FirewallStatus: a.FirewallStatus,
			Department: a.Department, LastSeenAt: a.LastSeenAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoints": out})
}

func (h *API) Overview(w http.ResponseWriter, r *http.Request) {
	auth, ok := middleware.AgentFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "agent context missing")
		return
	}
	stats, err := h.OverviewSvc.Stats(r.Context(), auth.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "OVERVIEW_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// MountAgentRoutes registers authenticated agent API routes.
func (h *API) MountAgentRoutes(r chi.Router, agentAuth middleware.AgentAuthenticator) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.AgentAuth(agentAuth))
		r.Post("/heartbeat", h.Heartbeat)
		r.Post("/alerts", h.UploadAlerts)
		r.Post("/decisions", h.UploadDecisions)
		r.Get("/iocs", h.ListIOCs)
		r.Get("/endpoints", h.ListEndpoints)
		r.Get("/overview", h.Overview)
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, models.ErrorResponse{Error: models.APIError{Code: code, Message: msg}})
}
