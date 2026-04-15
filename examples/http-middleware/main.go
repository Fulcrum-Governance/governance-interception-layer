// Example: HTTP governance proxy using GovernanceMiddleware.
//
// Wraps a mock downstream handler with pre-execution governance. The
// middleware reads the tool name from the X-Tool-Name header, evaluates
// it through the pipeline, and either forwards the request or returns
// HTTP 403 with a JSON deny body. Every decision is logged as structured
// JSON via SlogAuditPublisher.
//
// Run with: go run main.go
// Then in another terminal:
//   curl -i -H "X-Tool-Name: read_file" -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/
//   curl -i -H "X-Tool-Name: rm"        -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/
//   curl -i -H "X-Tool-Name: drop_table" -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fulcrum-governance/gil/governance"
)

func main() {
	// Static policies deny destructive tools; everything else flows through.
	cfg := governance.PipelineConfig{
		StaticPolicies: []governance.StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive filesystem op"},
			{Name: "block-drop-table", Tool: "drop_table", Action: "deny", Reason: "destructive database op"},
		},
	}

	// Structured JSON audit log to stdout. Deny decisions log at WARN.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	auditor := governance.NewSlogAuditPublisher(logger)

	pipeline := governance.NewPipeline(cfg, nil, nil, auditor)

	// Mock downstream handler — in a real deployment this would be a reverse
	// proxy to the tool backend. For the demo it just echoes what was allowed.
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "downstream handler invoked for tool=%q\n", r.Header.Get("X-Tool-Name"))
	})

	middleware := governance.NewMiddleware(pipeline, downstream, governance.MiddlewareConfig{
		TransportType: governance.TransportMCP,
	})

	fmt.Fprintln(os.Stderr, "GIL HTTP middleware listening on :8080")
	fmt.Fprintln(os.Stderr, "Try:")
	fmt.Fprintln(os.Stderr, `  curl -i -H "X-Tool-Name: read_file"  -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/`)
	fmt.Fprintln(os.Stderr, `  curl -i -H "X-Tool-Name: rm"         -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/`)
	fmt.Fprintln(os.Stderr, `  curl -i -H "X-Tool-Name: drop_table" -H "X-Agent-ID: a1" -H "X-Tenant-ID: t1" http://localhost:8080/`)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           middleware,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
