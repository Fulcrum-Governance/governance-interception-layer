// Package interceptors provides ready-to-use governance.Interceptor
// implementations that plug into the GIL pipeline without external dependencies.
package interceptors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fulcrum-governance/gil/governance"
)

// RateLimitConfig defines a token bucket rate limit.
//
// MaxRequests is the bucket capacity (burst limit) and the number of tokens
// the bucket holds when full. Window is the period over which the bucket
// refills from empty to MaxRequests; tokens are added continuously at
// MaxRequests / Window per unit time.
type RateLimitConfig struct {
	MaxRequests int
	Window      time.Duration
}

// RateLimiter tracks per-key request rates with a token bucket algorithm.
// Keys are derived per request by the ForAgent / ForTool / ForAgentTool
// helpers; each helper returns a governance.Interceptor that consumes
// one token per call against the relevant key.
type RateLimiter struct {
	config  RateLimitConfig
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens     int
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter with the given configuration.
// MaxRequests must be > 0 and Window must be > 0; otherwise every request
// is denied (the limiter is effectively closed).
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config:  cfg,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// allow consumes one token for key. Returns true if a token was available.
func (rl *RateLimiter) allow(key string) bool {
	if rl.config.MaxRequests <= 0 || rl.config.Window <= 0 {
		return false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.config.MaxRequests, lastRefill: now}
		rl.buckets[key] = b
	} else {
		// Refill based on elapsed time. One token every Window/MaxRequests.
		interval := rl.config.Window / time.Duration(rl.config.MaxRequests)
		if interval <= 0 {
			interval = 1
		}
		elapsed := now.Sub(b.lastRefill)
		add := int(elapsed / interval)
		if add > 0 {
			b.tokens += add
			if b.tokens > rl.config.MaxRequests {
				b.tokens = rl.config.MaxRequests
			}
			b.lastRefill = b.lastRefill.Add(interval * time.Duration(add))
		}
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// ForAgent returns an Interceptor that rate-limits by AgentID.
// Requests with an empty AgentID share the empty-string bucket.
func (rl *RateLimiter) ForAgent() governance.Interceptor {
	return rl.intercept(func(req *governance.GovernanceRequest) string {
		return req.AgentID
	})
}

// ForTool returns an Interceptor that rate-limits by ToolName.
func (rl *RateLimiter) ForTool() governance.Interceptor {
	return rl.intercept(func(req *governance.GovernanceRequest) string {
		return req.ToolName
	})
}

// ForAgentTool returns an Interceptor that rate-limits by the
// "agent:tool" combination, isolating per-agent quotas per tool.
func (rl *RateLimiter) ForAgentTool() governance.Interceptor {
	return rl.intercept(func(req *governance.GovernanceRequest) string {
		return req.AgentID + ":" + req.ToolName
	})
}

func (rl *RateLimiter) intercept(keyFn func(*governance.GovernanceRequest) string) governance.Interceptor {
	return func(_ context.Context, req *governance.GovernanceRequest) (*governance.InterceptorResult, error) {
		key := keyFn(req)
		if rl.allow(key) {
			return nil, nil
		}
		return &governance.InterceptorResult{
			Allowed: false,
			Action:  "deny",
			Reason:  fmt.Sprintf("rate limit exceeded: %d/%s for %s", rl.config.MaxRequests, rl.config.Window, key),
		}, nil
	}
}
