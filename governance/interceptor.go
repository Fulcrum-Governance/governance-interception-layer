package governance

import "context"

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
type InterceptorRegistry struct {
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
	r.interceptors[toolName] = fn
}

// Run executes the interceptor for the given tool, if one is registered.
// Returns nil, nil if no interceptor is registered.
func (r *InterceptorRegistry) Run(ctx context.Context, req *GovernanceRequest) (*InterceptorResult, error) {
	fn, ok := r.interceptors[req.ToolName]
	if !ok {
		return nil, nil
	}
	return fn(ctx, req)
}
