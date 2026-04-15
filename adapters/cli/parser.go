// Package cli provides the CLI transport adapter for the Governance
// Interception Layer. It governs agents that execute shell commands
// via run(command="...") patterns.
package cli

import (
	"fmt"
	"strings"

	"github.com/fulcrum-governance/gil/governance"
)

// ParseCommand splits a shell command string into pipe segments.
// It splits on unquoted '|' characters and returns each segment's
// command and arguments. Quoted strings (single and double) are
// preserved as single tokens. Basic escape sequences (\", \') are
// handled inside quoted strings.
//
// This parser handles pipe chains only. It does NOT handle &&, ||, ;,
// $(), or backticks — those represent separate commands, not pipes.
func ParseCommand(cmd string) ([]governance.PipeSegment, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil, fmt.Errorf("parse command: empty command")
	}

	rawSegments, err := splitPipes(cmd)
	if err != nil {
		return nil, fmt.Errorf("parse command: %w", err)
	}

	segments := make([]governance.PipeSegment, 0, len(rawSegments))
	for _, raw := range rawSegments {
		tokens, err := tokenize(raw)
		if err != nil {
			return nil, fmt.Errorf("parse command: %w", err)
		}
		if len(tokens) == 0 {
			return nil, fmt.Errorf("parse command: empty pipe segment")
		}
		segments = append(segments, governance.PipeSegment{
			Command: tokens[0],
			Args:    tokens[1:],
		})
	}

	return segments, nil
}

// splitPipes splits a command string on unquoted '|' characters.
func splitPipes(cmd string) ([]string, error) {
	var segments []string
	var current strings.Builder
	var inSingle, inDouble, escaped bool

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]

		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' && (inDouble || inSingle) {
			// Inside quotes, check if next char is an escapable quote.
			if i+1 < len(cmd) {
				next := cmd[i+1]
				if (inDouble && next == '"') || (inSingle && next == '\'') || next == '\\' {
					current.WriteByte(ch)
					current.WriteByte(next)
					i++
					continue
				}
			}
			current.WriteByte(ch)
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			current.WriteByte(ch)
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			current.WriteByte(ch)
			continue
		}

		if ch == '|' && !inSingle && !inDouble {
			segments = append(segments, current.String())
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced quotes in command")
	}

	segments = append(segments, current.String())
	return segments, nil
}

// tokenize splits a single pipe segment into command tokens, respecting
// quoted strings and basic escape sequences.
func tokenize(segment string) ([]string, error) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return nil, nil
	}

	var tokens []string
	var current strings.Builder
	var inSingle, inDouble bool

	for i := 0; i < len(segment); i++ {
		ch := segment[i]

		// Handle escape sequences inside quotes.
		if ch == '\\' && (inDouble || inSingle) {
			if i+1 < len(segment) {
				next := segment[i+1]
				if (inDouble && next == '"') || (inSingle && next == '\'') || next == '\\' {
					current.WriteByte(next)
					i++
					continue
				}
			}
			current.WriteByte(ch)
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}

		if (ch == ' ' || ch == '\t') && !inSingle && !inDouble {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteByte(ch)
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced quotes in segment %q", segment)
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}
