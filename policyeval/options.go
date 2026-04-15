package policyeval

import "time"

// Option configures the Evaluator.
type Option func(*Evaluator)

// WithMaxEvaluationTime sets the maximum time allowed for policy evaluation.
// If evaluation exceeds this duration, a warning is logged (if logger is set).
// Default: 10ms
func WithMaxEvaluationTime(d time.Duration) Option {
	return func(e *Evaluator) {
		e.maxEvaluationTime = d
	}
}

// WithLogger sets a logger for the evaluator.
// The logger interface is minimal to avoid dependencies.
func WithLogger(l Logger) Option {
	return func(e *Evaluator) {
		e.logger = l
	}
}

// WithExternalCallsEnabled enables or disables external HTTP calls for conditions.
// Default: false (disabled for security in proxy/SDK contexts).
func WithExternalCallsEnabled(enabled bool) Option {
	return func(e *Evaluator) {
		e.externalCallsEnabled = enabled
	}
}

// WithStopOnDeny configures whether to stop evaluating policies after the first deny.
// Default: true
func WithStopOnDeny(stop bool) Option {
	return func(e *Evaluator) {
		e.stopOnDeny = stop
	}
}

// Logger is a minimal logging interface for the evaluator.
// This allows the evaluator to log without depending on a specific logging library.
type Logger interface {
	Debug(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
}

// Field represents a structured log field.
type Field struct {
	Key   string
	Value interface{}
}

// noopLogger is a logger that does nothing.
type noopLogger struct{}

func (noopLogger) Debug(string, ...Field) {}
func (noopLogger) Warn(string, ...Field)  {}
