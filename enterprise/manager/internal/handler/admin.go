package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/middleware"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type AuthHandler struct {
	Auth *service.AuthService
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	resp, err := h.Auth.Login(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "LOGIN_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type AdminHandler struct {
	Admin        *service.AdminService
	OverviewSvc  *service.OverviewService
	EndpointsSvc *service.EndpointService
	FleetSvc     *service.FleetDetailService
}

func (h *AdminHandler) Overview(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	stats, err := h.OverviewSvc.Stats(r.Context(), user.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "OVERVIEW_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *AdminHandler) Alerts(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	alerts, err := h.Admin.Alerts(r.Context(), user.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ALERTS_FAILED", err.Error())
		return
	}
	if alerts == nil {
		alerts = []models.AlertSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"alerts": alerts})
}

func (h *AdminHandler) Endpoints(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	agents, err := h.EndpointsSvc.ListForOrg(r.Context(), user.OrganizationID)
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

func (h *AdminHandler) EndpointDetail(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "MISSING_ID", "endpoint id required")
		return
	}
	detail, err := h.FleetSvc.Get(r.Context(), user.OrganizationID, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *AdminHandler) Incidents(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	inc, err := h.Admin.Incidents(r.Context(), user.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INCIDENTS_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"incidents": inc})
}

func (h *AdminHandler) AuditLogs(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	logs, err := h.Admin.AuditLogs(r.Context(), user.OrganizationID, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "AUDIT_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"audit_logs": logs})
}

func (h *AdminHandler) RevokeIOC(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	var req models.ThreatIntelRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	version, revoked, err := h.Admin.RevokeIOCs(r.Context(), user.OrganizationID, user.UserID, req.IPs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"revoked": revoked, "ioc_version": version})
}

func (h *AdminHandler) ThreatIntel(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	iocs, err := h.Admin.ThreatIntel(r.Context(), user.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "IOC_FAILED", err.Error())
		return
	}
	if iocs == nil {
		iocs = []models.IOC{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"iocs": iocs})
}

func (h *AdminHandler) ImportFeed(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	var req models.ThreatFeedImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	n, ver, err := h.Admin.ImportFeed(r.Context(), user.OrganizationID, user.UserID, req.Source, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "IMPORT_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"imported": n, "ioc_version": ver})
}

func (h *AdminHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
		return
	}
	writeJSON(w, http.StatusOK, models.UserInfo{
		ID: user.UserID, Email: user.Email, Role: user.Role, OrganizationID: user.OrganizationID,
	})
}

func MountAdminRoutes(r chi.Router, jwtSecret string, auth *service.AuthService, admin *AdminHandler) {
	r.Post("/auth/login", (&AuthHandler{Auth: auth}).Login)
	r.Group(func(r chi.Router) {
		r.Use(middleware.JWTAuth(jwtSecret))
		r.Use(middleware.ReadOnly)
		r.Get("/admin/me", admin.Me)
		r.Get("/admin/overview", admin.Overview)
		r.Get("/admin/alerts", admin.Alerts)
		r.Get("/admin/incidents", admin.Incidents)
		r.Get("/admin/endpoints", admin.Endpoints)
		r.Get("/admin/endpoints/{id}", admin.EndpointDetail)
		r.Get("/admin/threat-intel", admin.ThreatIntel)
		r.Get("/admin/audit-logs", admin.AuditLogs)
		r.With(middleware.RequireRole("admin", "soc_analyst")).Post("/admin/threat-feed/import", admin.ImportFeed)
		r.With(middleware.RequireRole("admin", "soc_analyst")).Post("/admin/threat-intel/revoke", admin.RevokeIOC)
	})
}
