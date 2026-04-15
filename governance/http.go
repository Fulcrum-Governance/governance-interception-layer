package governance

import (
	"encoding/json"
	"net/http"
	"strings"
)

// MiddlewareConfig configures GovernanceMiddleware. Zero-value fields fall
// back to documented defaults.
type MiddlewareConfig struct {
	// ToolNameHeader is read to populate GovernanceRequest.ToolName.
	// Default: "X-Tool-Name".
	ToolNameHeader string

	// AgentIDHeader is read to populate GovernanceRequest.AgentID.
	// Default: "X-Agent-ID".
	AgentIDHeader string

	// TenantIDHeader is read to populate GovernanceRequest.TenantID.
	// Default: "X-Tenant-ID".
	TenantIDHeader string

	// TransportType is the transport recorded on GovernanceRequest.
	// Default: TransportMCP.
	TransportType TransportType

	// ToolNameFromPath, if true, uses the URL path as the tool name when the
	// tool-name header is absent.
	ToolNameFromPath bool
}

// Response header names. These are also written on deny responses so that
// clients always see the governance verdict in the same fields.
const (
	HeaderGovernanceAction     = "X-Governance-Action"
	HeaderGovernanceReason     = "X-Governance-Reason"
	HeaderGovernanceEnvelopeID = "X-Governance-Envelope-ID"
	HeaderGovernanceRequestID  = "X-Governance-Request-ID"
	HeaderGovernanceDryRun     = "X-Governance-Dry-Run"
)

// GovernanceMiddleware wraps an http.Handler with pre-execution governance.
// If Next is nil, the middleware acts as a standalone decision endpoint that
// returns the decision as a JSON body.
type GovernanceMiddleware struct {
	Pipeline *Pipeline
	Next     http.Handler
	Config   MiddlewareConfig
}

// NewMiddleware creates a GovernanceMiddleware. Zero-value config fields are
// filled with defaults; the returned middleware is safe to use as an
// http.Handler.
func NewMiddleware(pipeline *Pipeline, next http.Handler, cfg MiddlewareConfig) *GovernanceMiddleware {
	if cfg.ToolNameHeader == "" {
		cfg.ToolNameHeader = "X-Tool-Name"
	}
	if cfg.AgentIDHeader == "" {
		cfg.AgentIDHeader = "X-Agent-ID"
	}
	if cfg.TenantIDHeader == "" {
		cfg.TenantIDHeader = "X-Tenant-ID"
	}
	if cfg.TransportType == "" {
		cfg.TransportType = TransportMCP
	}
	return &GovernanceMiddleware{Pipeline: pipeline, Next: next, Config: cfg}
}

// ServeHTTP evaluates the request through the governance pipeline. On deny,
// it writes HTTP 403 with a JSON body. On allow/warn, it writes governance
// response headers and either forwards to Next or returns the decision as
// JSON when Next is nil.
func (m *GovernanceMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	toolName := r.Header.Get(m.Config.ToolNameHeader)
	if toolName == "" && m.Config.ToolNameFromPath {
		toolName = strings.TrimPrefix(r.URL.Path, "/")
	}

	gReq := &GovernanceRequest{
		Transport: m.Config.TransportType,
		ToolName:  toolName,
		AgentID:   r.Header.Get(m.Config.AgentIDHeader),
		TenantID:  r.Header.Get(m.Config.TenantIDHeader),
	}

	decision, err := m.Pipeline.Evaluate(r.Context(), gReq)
	if err != nil {
		http.Error(w, "governance pipeline error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeGovernanceHeaders(w, decision)

	if !decision.Allowed() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"action":     decision.Action,
			"reason":     decision.Reason,
			"request_id": decision.RequestID,
		})
		return
	}

	if m.Next == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"action":      decision.Action,
			"reason":      decision.Reason,
			"request_id":  decision.RequestID,
			"envelope_id": decision.EnvelopeID,
			"dry_run":     decision.DryRun,
		})
		return
	}

	m.Next.ServeHTTP(w, r)
}

func writeGovernanceHeaders(w http.ResponseWriter, d *GovernanceDecision) {
	w.Header().Set(HeaderGovernanceAction, d.Action)
	if d.Reason != "" {
		w.Header().Set(HeaderGovernanceReason, d.Reason)
	}
	if d.EnvelopeID != "" {
		w.Header().Set(HeaderGovernanceEnvelopeID, d.EnvelopeID)
	}
	if d.RequestID != "" {
		w.Header().Set(HeaderGovernanceRequestID, d.RequestID)
	}
	if d.DryRun {
		w.Header().Set(HeaderGovernanceDryRun, "true")
	}
}
