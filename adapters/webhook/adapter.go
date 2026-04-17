// Package webhook provides a TransportAdapter and HTTP handler for
// webhook-style tool invocations: an upstream agent POSTs a JSON payload
// describing the tool call, the handler runs governance, and either
// forwards the request to a downstream service or returns the decision.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/fulcrum-governance/gil/governance"
)

// WebhookPayload is the expected JSON body of an incoming webhook tool call.
type WebhookPayload struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	AgentID   string         `json:"agent_id"`
	TenantID  string         `json:"tenant_id"`
	TraceID   string         `json:"trace_id,omitempty"`
}

// Adapter implements governance.TransportAdapter for webhook payloads.
type Adapter struct {
	// DefaultTenantID is applied when the payload does not specify one.
	DefaultTenantID string
}

// NewAdapter returns a webhook adapter with an optional default tenant.
func NewAdapter(defaultTenantID string) *Adapter {
	return &Adapter{DefaultTenantID: defaultTenantID}
}

// Type returns TransportWebhook.
func (a *Adapter) Type() governance.TransportType { return governance.TransportWebhook }

// ParseRequest accepts *http.Request, *WebhookPayload, WebhookPayload, or
// a JSON byte slice. For *http.Request, it reads (and replaces) the body.
func (a *Adapter) ParseRequest(_ context.Context, raw any) (*governance.GovernanceRequest, error) {
	var payload *WebhookPayload
	switch v := raw.(type) {
	case *WebhookPayload:
		payload = v
	case WebhookPayload:
		payload = &v
	case json.RawMessage:
		payload = &WebhookPayload{}
		if err := json.Unmarshal(v, payload); err != nil {
			return nil, governance.NewParseError(governance.TransportWebhook, "unmarshal payload", err)
		}
	case []byte:
		payload = &WebhookPayload{}
		if err := json.Unmarshal(v, payload); err != nil {
			return nil, governance.NewParseError(governance.TransportWebhook, "unmarshal payload", err)
		}
	case *http.Request:
		body, err := io.ReadAll(v.Body)
		if err != nil {
			return nil, governance.NewParseError(governance.TransportWebhook, "read request body", err)
		}
		_ = v.Body.Close()
		// Restore body for downstream consumers.
		v.Body = io.NopCloser(bytes.NewReader(body))
		payload = &WebhookPayload{}
		if err := json.Unmarshal(body, payload); err != nil {
			return nil, governance.NewParseError(governance.TransportWebhook, "unmarshal request body", err)
		}
	default:
		return nil, governance.NewParseError(governance.TransportWebhook, fmt.Sprintf("unsupported raw type %T", raw), nil)
	}

	if payload.Tool == "" {
		return nil, governance.NewParseError(governance.TransportWebhook, "tool field is required", nil)
	}
	tenantID := payload.TenantID
	if tenantID == "" {
		tenantID = a.DefaultTenantID
	}

	return &governance.GovernanceRequest{
		RequestID: uuid.New().String(),
		Transport: governance.TransportWebhook,
		AgentID:   payload.AgentID,
		TenantID:  tenantID,
		ToolName:  payload.Tool,
		Action:    "webhook/invoke",
		Arguments: payload.Arguments,
		TraceID:   payload.TraceID,
	}, nil
}

// ForwardGoverned is a no-op; the Handler() function performs forwarding
// when a forwardURL is configured.
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
	return nil, nil
}

// InspectResponse returns a benign result.
func (a *Adapter) InspectResponse(_ context.Context, _ *governance.ToolResponse) (*governance.ResponseInspection, error) {
	return &governance.ResponseInspection{Safe: true}, nil
}

// EmitGovernanceMetadata is a no-op; the Handler() function writes
// governance headers directly onto the http.ResponseWriter.
func (a *Adapter) EmitGovernanceMetadata(_ context.Context, _ *governance.ToolResponse, _ *governance.GovernanceDecision) error {
	return nil
}

// Handler returns an http.HandlerFunc that runs the governance pipeline
// on incoming webhook payloads.
//
// Behavior:
//   - Parse error → 400 Bad Request with JSON error body.
//   - Pipeline error → 500 Internal Server Error.
//   - Decision is not allowed → 403 Forbidden with the decision JSON.
//   - Decision is allowed and forwardURL == "" → 200 OK with the decision JSON.
//   - Decision is allowed and forwardURL != "" → POST the original payload
//     to forwardURL and stream the downstream response back to the caller.
//
// Governance headers (X-Governance-Action, X-Governance-Reason,
// X-Governance-Envelope-ID) are added to every response.
func Handler(pipeline *governance.Pipeline, forwardURL string) http.HandlerFunc {
	adapter := NewAdapter("")
	client := &http.Client{}
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		_ = r.Body.Close()

		req, err := adapter.ParseRequest(r.Context(), body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		decision, err := pipeline.Evaluate(r.Context(), req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "governance: "+err.Error())
			return
		}

		writeGovernanceHeaders(w, decision)
		if !decision.Allowed() {
			writeJSON(w, http.StatusForbidden, decision)
			return
		}

		if forwardURL == "" {
			writeJSON(w, http.StatusOK, decision)
			return
		}

		fwd, err := http.NewRequestWithContext(r.Context(), http.MethodPost, forwardURL, bytes.NewReader(body))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "build forward request: "+err.Error())
			return
		}
		fwd.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(fwd)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, "forward: "+err.Error())
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func writeGovernanceHeaders(w http.ResponseWriter, d *governance.GovernanceDecision) {
	w.Header().Set("X-Governance-Action", d.Action)
	if d.Reason != "" {
		w.Header().Set("X-Governance-Reason", d.Reason)
	}
	if d.EnvelopeID != "" {
		w.Header().Set("X-Governance-Envelope-ID", d.EnvelopeID)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
