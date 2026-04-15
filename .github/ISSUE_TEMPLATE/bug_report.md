---
name: Bug report
about: Report a defect in GIL
title: "[bug] "
labels: bug
---

### Environment

- GIL version or commit:
- Go version (`go version`):
- OS and architecture:

### Steps to reproduce

1.
2.
3.

A minimal reproducer that compiles is far more useful than a long description.
If you can, paste the code inline in a Go fenced block.

```go
// reproducer here
```

### Expected behaviour

What you expected GIL to do.

### Actual behaviour

What actually happened. Include any error messages, panics, or unexpected
decisions verbatim. If the issue is a surprising deny/allow, include the full
`GovernanceDecision` (`Action`, `Reason`, `PolicyID`, `TrustScore`).

### Additional context

Anything else that might matter: custom interceptors, non-default
`PipelineConfig`, wrapping libraries, whether the problem is reproducible
with the stock examples, etc.
