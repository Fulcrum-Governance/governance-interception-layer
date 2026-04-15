// Package grpc provides a gRPC unary server interceptor that routes
// every RPC through the governance pipeline before the handler runs.
//
// The adapter lives in its own go.mod so the root GIL module stays free
// of the google.golang.org/grpc dependency tree. Import this adapter only
// in services that already speak gRPC.
package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fulcrum-governance/gil/governance"
)

// Default metadata header keys used to extract identity from a gRPC call.
const (
	DefaultAgentMetadataKey  = "x-agent-id"
	DefaultTenantMetadataKey = "x-tenant-id"
	DefaultTraceMetadataKey  = "x-trace-id"
)

// CallInfo describes a gRPC unary call in transport-neutral terms.
// It is what ParseRequest expects to receive as its raw input.
type CallInfo struct {
	Method   string      // Full gRPC method name, e.g., "/svc.Service/Method"
	Metadata metadata.MD // Incoming metadata headers
	AgentID  string      // Optional override; falls back to metadata
	TenantID string      // Optional override; falls back to metadata
}

// Adapter implements governance.TransportAdapter for gRPC unary calls.
type Adapter struct {
	// AgentMetadataKey overrides the metadata header used for AgentID.
	// Defaults to DefaultAgentMetadataKey when empty.
	AgentMetadataKey string
	// TenantMetadataKey overrides the metadata header used for TenantID.
	// Defaults to DefaultTenantMetadataKey when empty.
	TenantMetadataKey string
	// DefaultTenantID is used when no tenant header is present.
	DefaultTenantID string
}

// NewAdapter returns an Adapter with default header keys.
func NewAdapter(defaultTenantID string) *Adapter {
	return &Adapter{DefaultTenantID: defaultTenantID}
}

// Type returns TransportGRPC.
func (a *Adapter) Type() governance.TransportType { return governance.TransportGRPC }

// ParseRequest converts a *CallInfo into a canonical GovernanceRequest.
func (a *Adapter) ParseRequest(_ context.Context, raw any) (*governance.GovernanceRequest, error) {
	info, ok := raw.(*CallInfo)
	if !ok {
		return nil, fmt.Errorf("unsupported raw type %T for gRPC adapter", raw)
	}
	if info.Method == "" {
		return nil, fmt.Errorf("gRPC CallInfo.Method is required")
	}

	agentID := info.AgentID
	tenantID := info.TenantID
	traceID := ""
	if info.Metadata != nil {
		if agentID == "" {
			agentID = firstMetadataValue(info.Metadata, a.agentKey())
		}
		if tenantID == "" {
			tenantID = firstMetadataValue(info.Metadata, a.tenantKey())
		}
		traceID = firstMetadataValue(info.Metadata, DefaultTraceMetadataKey)
	}
	if tenantID == "" {
		tenantID = a.DefaultTenantID
	}

	return &governance.GovernanceRequest{
		RequestID: uuid.New().String(),
		Transport: governance.TransportGRPC,
		AgentID:   agentID,
		TenantID:  tenantID,
		ToolName:  info.Method,
		Action:    "grpc/unary",
		TraceID:   traceID,
	}, nil
}

// ForwardGoverned is a no-op for gRPC. Forwarding the actual call is the
// responsibility of the surrounding gRPC server interceptor chain.
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
	return nil, nil
}

// InspectResponse returns a benign inspection result; gRPC bytes are opaque.
func (a *Adapter) InspectResponse(_ context.Context, _ *governance.ToolResponse) (*governance.ResponseInspection, error) {
	return &governance.ResponseInspection{Safe: true}, nil
}

// EmitGovernanceMetadata is a no-op; gRPC trailers are emitted by the
// interceptor returned from UnaryInterceptor.
func (a *Adapter) EmitGovernanceMetadata(_ context.Context, _ *governance.ToolResponse, _ *governance.GovernanceDecision) error {
	return nil
}

func (a *Adapter) agentKey() string {
	if a.AgentMetadataKey != "" {
		return a.AgentMetadataKey
	}
	return DefaultAgentMetadataKey
}

func (a *Adapter) tenantKey() string {
	if a.TenantMetadataKey != "" {
		return a.TenantMetadataKey
	}
	return DefaultTenantMetadataKey
}

// UnaryInterceptor returns a grpc.UnaryServerInterceptor that evaluates each
// RPC through pipeline before invoking the actual handler. Denied requests
// return codes.PermissionDenied with the governance reason as the message.
//
// adapter may be nil; in that case a default-configured adapter is used.
func UnaryInterceptor(pipeline *governance.Pipeline, adapter *Adapter) grpclib.UnaryServerInterceptor {
	if adapter == nil {
		adapter = &Adapter{}
	}
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		gReq, err := adapter.ParseRequest(ctx, &CallInfo{
			Method:   info.FullMethod,
			Metadata: md,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "governance: parse request: %v", err)
		}
		decision, err := pipeline.Evaluate(ctx, gReq)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "governance: evaluate: %v", err)
		}
		if !decision.Allowed() {
			reason := decision.Reason
			if reason == "" {
				reason = decision.Action
			}
			return nil, status.Errorf(codes.PermissionDenied, "governance: %s", reason)
		}
		return handler(ctx, req)
	}
}

func firstMetadataValue(md metadata.MD, key string) string {
	if vs := md.Get(key); len(vs) > 0 {
		return vs[0]
	}
	return ""
}
