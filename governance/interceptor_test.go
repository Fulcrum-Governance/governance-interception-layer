package governance

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestInterceptorRegistry_ConcurrentRegisterAndRun exercises the registry
// from many goroutines simultaneously. Before the mutex fix, this panicked
// with "concurrent map read and map write" under -race.
func TestInterceptorRegistry_ConcurrentRegisterAndRun(t *testing.T) {
	r := NewInterceptorRegistry()

	// Seed one entry so Run sometimes finds a match.
	r.Register("seed", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: true, Action: "allow"}, nil
	})

	const n = 1000
	var wg sync.WaitGroup
	wg.Add(n * 2)

	var runs atomic.Int64
	var registers atomic.Int64

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			r.Register("tool-"+strconv.Itoa(i), func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
				return &InterceptorResult{Allowed: true, Action: "allow"}, nil
			})
			registers.Add(1)
		}(i)
	}

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			req := &GovernanceRequest{ToolName: "tool-" + strconv.Itoa(i%100)}
			if _, err := r.Run(context.Background(), req); err != nil {
				t.Errorf("Run returned error: %v", err)
			}
			runs.Add(1)
		}(i)
	}

	wg.Wait()

	if registers.Load() != n {
		t.Errorf("expected %d registers, got %d", n, registers.Load())
	}
	if runs.Load() != n {
		t.Errorf("expected %d runs, got %d", n, runs.Load())
	}
}

// TestInterceptorRegistry_RunReleasesLockBeforeUserCode verifies that the
// registry's read lock is released before the interceptor function executes,
// so a Register call from inside an interceptor cannot deadlock.
func TestInterceptorRegistry_RunReleasesLockBeforeUserCode(t *testing.T) {
	r := NewInterceptorRegistry()

	r.Register("recursive", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		// If Run held the read lock, this Register (write lock) would deadlock.
		r.Register("registered-from-interceptor", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
			return &InterceptorResult{Allowed: true, Action: "allow"}, nil
		})
		return &InterceptorResult{Allowed: true, Action: "allow"}, nil
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		req := &GovernanceRequest{ToolName: "recursive"}
		if _, err := r.Run(context.Background(), req); err != nil {
			t.Errorf("Run error: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run deadlocked: lock was held during user code execution")
	}
}
