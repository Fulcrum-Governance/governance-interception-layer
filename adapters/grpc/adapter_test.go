package grpc

import (
	"context"
	"strings"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fulcrum-governance/gil/governance"
)

func newPipeline(t *testing.T, deny bool, denyTool string) *governance.Pipeline {
	t.Helper()
	cfg := governance.PipelineConfig{}
	if deny {
		cfg.StaticPolicies = []governance.StaticPolicyRule{{
			Name:   "deny-test",
			Tool:   denyTool,
			Action: "deny",
			Reason: "blocked by test policy",
		}}
	}
	return governance.NewPipeline(cfg, nil, nil, nil)
}

func TestAdapter_Type(t *testing.T) {
	a := NewAdapter("tenant-default")
	if a.Type() != governance.TransportGRPC {
		t.Fatalf("expected TransportGRPC, got %s", a.Type())
	}
}

func TestAdapter_ParseRequest_FromCallInfo(t *testing.T) {
	a := NewAdapter("tenant-default")
	md := metadata.New(map[string]string{
		DefaultAgentMetadataKey:  "agent-7",
		DefaultTenantMetadataKey: "tenant-7",
		DefaultTraceMetadataKey:  "trace-xyz",
	})
	req, err := a.ParseRequest(context.Background(), &CallInfo{
		Method:   "/svc.Service/DoThing",
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.Transport != governance.TransportGRPC {
		t.Errorf("transport = %s, want grpc", req.Transport)
	}
	if req.ToolName != "/svc.Service/DoThing" {
		t.Errorf("tool name = %s", req.ToolName)
	}
	if req.AgentID != "agent-7" || req.TenantID != "tenant-7" || req.TraceID != "trace-xyz" {
		t.Errorf("identity not propagated: %+v", req)
	}
}

func TestAdapter_ParseRequest_TenantFallback(t *testing.T) {
	a := NewAdapter("tenant-default")
	req, err := a.ParseRequest(context.Background(), &CallInfo{
		Method:   "/svc.Service/M",
		Metadata: metadata.MD{}, // empty
	})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.TenantID != "tenant-default" {
		t.Errorf("expected tenant-default fallback, got %q", req.TenantID)
	}
	if req.AgentID != "" {
		t.Errorf("expected empty agent, got %q", req.AgentID)
	}
}

func TestAdapter_ParseRequest_RejectsUnknownType(t *testing.T) {
	a := NewAdapter("")
	if _, err := a.ParseRequest(context.Background(), "not a CallInfo"); err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if _, err := a.ParseRequest(context.Background(), &CallInfo{}); err == nil {
		t.Fatal("expected error for empty Method")
	}
}

func TestUnaryInterceptor_Allowed(t *testing.T) {
	pipe := newPipeline(t, false, "")
	intercept := UnaryInterceptor(pipe, NewAdapter(""))

	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}
	resp, err := intercept(context.Background(), nil, &grpclib.UnaryServerInfo{FullMethod: "/svc.Svc/Allowed"}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("downstream handler was not called")
	}
	if resp != "ok" {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestUnaryInterceptor_Denied(t *testing.T) {
	pipe := newPipeline(t, true, "/svc.Svc/Forbidden")
	intercept := UnaryInterceptor(pipe, NewAdapter(""))

	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return nil, nil
	}
	_, err := intercept(context.Background(), nil, &grpclib.UnaryServerInfo{FullMethod: "/svc.Svc/Forbidden"}, handler)
	if err == nil {
		t.Fatal("expected denial error")
	}
	if called {
		t.Fatal("handler must NOT be called on deny")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %s", st.Code())
	}
	if !strings.Contains(st.Message(), "blocked by test policy") {
		t.Fatalf("expected reason in message, got %q", st.Message())
	}
}

func TestUnaryInterceptor_MetadataExtraction(t *testing.T) {
	pipe := newPipeline(t, false, "")
	intercept := UnaryInterceptor(pipe, NewAdapter(""))

	ctx := metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
		DefaultAgentMetadataKey:  "alice",
		DefaultTenantMetadataKey: "acme",
	}))

	// Use a custom interceptor on top to capture the parsed request via a
	// chained handler that inspects the context — but the request itself is
	// only visible inside ParseRequest. Easier: re-call ParseRequest with the
	// same metadata to verify extraction is wired through.
	a := NewAdapter("")
	md, _ := metadata.FromIncomingContext(ctx)
	req, err := a.ParseRequest(ctx, &CallInfo{Method: "/svc/Method", Metadata: md})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.AgentID != "alice" || req.TenantID != "acme" {
		t.Fatalf("metadata not extracted: %+v", req)
	}

	// And verify the interceptor itself doesn't error when md is present.
	if _, err := intercept(ctx, nil, &grpclib.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req any) (any, error) { return nil, nil }); err != nil {
		t.Fatalf("interceptor with metadata failed: %v", err)
	}
}

func TestUnaryInterceptor_NilAdapterDefaults(t *testing.T) {
	pipe := newPipeline(t, false, "")
	// Passing nil adapter must not panic.
	intercept := UnaryInterceptor(pipe, nil)
	if _, err := intercept(context.Background(), nil, &grpclib.UnaryServerInfo{FullMethod: "/svc/M"}, func(ctx context.Context, req any) (any, error) { return "ok", nil }); err != nil {
		t.Fatalf("nil adapter path failed: %v", err)
	}
}
