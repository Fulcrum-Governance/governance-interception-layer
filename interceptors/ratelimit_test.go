package interceptors

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fulcrum-governance/gil/governance"
)

func newReq(agent, tool string) *governance.GovernanceRequest {
	return &governance.GovernanceRequest{AgentID: agent, ToolName: tool}
}

// runIntercept is a tiny helper to call an interceptor and classify the result.
func runIntercept(t *testing.T, fn governance.Interceptor, req *governance.GovernanceRequest) (allowed bool, reason string) {
	t.Helper()
	res, err := fn(context.Background(), req)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if res == nil {
		return true, ""
	}
	return res.Allowed, res.Reason
}

func TestRateLimiter_WithinLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 5, Window: time.Second})
	fn := rl.ForAgent()

	for i := 0; i < 5; i++ {
		allowed, reason := runIntercept(t, fn, newReq("agent-1", "tool"))
		if !allowed {
			t.Fatalf("request %d: expected allow, got deny (%s)", i+1, reason)
		}
	}
}

func TestRateLimiter_ExceedsLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 3, Window: time.Second})
	// Freeze time so the bucket cannot refill mid-test.
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }

	fn := rl.ForAgent()
	for i := 0; i < 3; i++ {
		if allowed, reason := runIntercept(t, fn, newReq("a", "t")); !allowed {
			t.Fatalf("request %d should allow, got deny (%s)", i+1, reason)
		}
	}

	allowed, reason := runIntercept(t, fn, newReq("a", "t"))
	if allowed {
		t.Fatalf("expected 4th request to be denied")
	}
	if !strings.Contains(reason, "rate limit exceeded") || !strings.Contains(reason, "3/1s") || !strings.Contains(reason, "for a") {
		t.Fatalf("unexpected deny reason: %q", reason)
	}
}

func TestRateLimiter_IndependentBuckets(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 2, Window: time.Second})
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }

	fn := rl.ForAgent()

	// Two agents each get their own quota.
	for _, agent := range []string{"alice", "bob"} {
		for i := 0; i < 2; i++ {
			if allowed, _ := runIntercept(t, fn, newReq(agent, "tool")); !allowed {
				t.Fatalf("agent %s req %d should allow", agent, i+1)
			}
		}
		if allowed, _ := runIntercept(t, fn, newReq(agent, "tool")); allowed {
			t.Fatalf("agent %s 3rd req should deny", agent)
		}
	}
}

func TestRateLimiter_RefillAfterWindow(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 2, Window: 100 * time.Millisecond})
	current := time.Now()
	rl.now = func() time.Time { return current }

	fn := rl.ForAgent()
	// Drain.
	for i := 0; i < 2; i++ {
		if allowed, _ := runIntercept(t, fn, newReq("a", "t")); !allowed {
			t.Fatalf("drain %d should allow", i+1)
		}
	}
	if allowed, _ := runIntercept(t, fn, newReq("a", "t")); allowed {
		t.Fatalf("immediately after drain should deny")
	}

	// Advance one full window — bucket should refill to MaxRequests.
	current = current.Add(100 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if allowed, reason := runIntercept(t, fn, newReq("a", "t")); !allowed {
			t.Fatalf("after refill %d should allow, got: %s", i+1, reason)
		}
	}
	if allowed, _ := runIntercept(t, fn, newReq("a", "t")); allowed {
		t.Fatalf("post-refill 3rd should deny")
	}

	// Half window — should add 1 token (MaxRequests=2, half-window = 1).
	current = current.Add(50 * time.Millisecond)
	if allowed, _ := runIntercept(t, fn, newReq("a", "t")); !allowed {
		t.Fatalf("partial refill should allow one")
	}
	if allowed, _ := runIntercept(t, fn, newReq("a", "t")); allowed {
		t.Fatalf("partial refill should not allow two")
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 50, Window: time.Hour})
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }

	fn := rl.ForAgent()

	const goroutines = 20
	const perG = 10 // 200 attempts total against a 50-token bucket
	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				ok, _ := runIntercept(t, fn, newReq("a", "t"))
				if ok {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&allowed); got != 50 {
		t.Fatalf("concurrent test: expected exactly 50 allows under frozen clock, got %d", got)
	}
}

func TestRateLimiter_ForAgentVsToolVsAgentTool(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 1, Window: time.Hour})
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }

	t.Run("ForAgent", func(t *testing.T) {
		rl.buckets = make(map[string]*bucket)
		fn := rl.ForAgent()
		// Same agent, different tool — keyed only by agent, second call denies.
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-1")); !allowed {
			t.Fatalf("first should allow")
		}
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-2")); allowed {
			t.Fatalf("same agent, different tool should still deny under ForAgent")
		}
	})

	t.Run("ForTool", func(t *testing.T) {
		rl.buckets = make(map[string]*bucket)
		fn := rl.ForTool()
		// Same tool, different agent — keyed only by tool, second call denies.
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-1")); !allowed {
			t.Fatalf("first should allow")
		}
		if allowed, _ := runIntercept(t, fn, newReq("b", "tool-1")); allowed {
			t.Fatalf("same tool, different agent should still deny under ForTool")
		}
	})

	t.Run("ForAgentTool", func(t *testing.T) {
		rl.buckets = make(map[string]*bucket)
		fn := rl.ForAgentTool()
		// agent:tool — different agent OR different tool → independent buckets.
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-1")); !allowed {
			t.Fatalf("a/tool-1 first should allow")
		}
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-1")); allowed {
			t.Fatalf("a/tool-1 second should deny")
		}
		if allowed, _ := runIntercept(t, fn, newReq("b", "tool-1")); !allowed {
			t.Fatalf("b/tool-1 first should allow (different agent)")
		}
		if allowed, _ := runIntercept(t, fn, newReq("a", "tool-2")); !allowed {
			t.Fatalf("a/tool-2 first should allow (different tool)")
		}
	})
}

func TestRateLimiter_ZeroConfigDeniesAll(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{MaxRequests: 0, Window: time.Second})
	fn := rl.ForAgent()
	if allowed, _ := runIntercept(t, fn, newReq("a", "t")); allowed {
		t.Fatalf("zero MaxRequests should deny everything")
	}
}
