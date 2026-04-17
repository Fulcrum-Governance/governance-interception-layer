package governance

import (
	"encoding/json"
	"testing"
)

func TestDecisionMode_Valid(t *testing.T) {
	valid := []DecisionMode{
		DecisionModeDeterministic,
		DecisionModeClassified,
		DecisionModeProved,
		DecisionModeHumanApproved,
	}
	for _, m := range valid {
		if !m.Valid() {
			t.Errorf("%q should be valid", m)
		}
	}
}

func TestDecisionMode_Invalid(t *testing.T) {
	invalid := []DecisionMode{
		"",
		"governed",  // the retired generic term
		"unknown",
		"Deterministic", // case-sensitive: capital D must not match
		"probable",
	}
	for _, m := range invalid {
		if m.Valid() {
			t.Errorf("%q should NOT be valid", m)
		}
	}
}

func TestDecisionMode_WireFormat(t *testing.T) {
	// Pin the serialized strings so downstream consumers (audit sinks, IR
	// emitters, dashboards) can rely on them. Changing any of these is a
	// breaking change for the audit contract.
	want := map[DecisionMode]string{
		DecisionModeDeterministic: "deterministic",
		DecisionModeClassified:    "classified",
		DecisionModeProved:        "proved",
		DecisionModeHumanApproved: "human_approved",
	}
	for mode, expected := range want {
		if string(mode) != expected {
			t.Errorf("%v underlying string = %q, want %q", mode, string(mode), expected)
		}
		b, err := json.Marshal(mode)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", mode, err)
		}
		// json.Marshal of a string is quoted.
		if got := string(b); got != `"`+expected+`"` {
			t.Errorf("json.Marshal(%v) = %s, want %q", mode, got, `"`+expected+`"`)
		}
	}
}

func TestDecisionMode_ZeroValueIsEmptyString(t *testing.T) {
	// Backwards compatibility anchor: a struct field of type DecisionMode
	// defaults to "" (empty string), which is NOT Valid. Callers that don't
	// set the mode get an easily detectable "unknown" sentinel.
	var m DecisionMode
	if m != "" {
		t.Errorf("zero value = %q, want empty string", m)
	}
	if m.Valid() {
		t.Error("zero value must not be Valid")
	}
}
