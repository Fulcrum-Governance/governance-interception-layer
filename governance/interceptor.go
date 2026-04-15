package governance

import (
	"context"
	"sync"
)

// Interceptor is called before forwarding a governed request.
// Returning a non-nil InterceptorResult with Allowed=false blocks the call.
// Returning nil means no domain-specific governance applies.
type Interceptor func(ctx context.Context, req *GovernanceRequest) (*InterceptorResult, error)

// InterceptorResult holds the outcome of a domain-specific interceptor.
type InterceptorResult struct {
	Allowed bool
	Action  string
	Reason  string
}

// InterceptorRegistry maps tool names to domain-specific interceptors.
// Safe for concurrent Register / Run calls.
type InterceptorRegistry struct {
	mu           sync.RWMutex
	interceptors map[string]Interceptor
}

// NewInterceptorRegistry creates an empty registry.
func NewInterceptorRegistry() *InterceptorRegistry {
	return &InterceptorRegistry{
		interceptors: make(map[string]Interceptor),
	}
}

// Register adds a domain-specific interceptor for a tool name.
func (r *InterceptorRegistry) Register(toolName string, fn Interceptor) {
	r.mu.Lock()
	r.interceptors[toolName] = fn
	r.mu.Unlock()
}

// Run executes the interceptor for the given tool, if one is registered.
// Returns nil, nil if no interceptor is registered.
// The lock is released before invoking the interceptor so user code never
// runs while holding the registry lock.
func (r *InterceptorRegistry) Run(ctx context.Context, req *GovernanceRequest) (*InterceptorResult, error) {
	r.mu.RLock()
	fn, ok := r.interceptors[req.ToolName]
	r.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	return fn(ctx, req)
}
