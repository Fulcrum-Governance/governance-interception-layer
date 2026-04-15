package policyeval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSRF Protection: Block requests to internal/private networks
var (
	blockedIPRanges = []string{
		"127.0.0.0/8",    // Loopback
		"10.0.0.0/8",     // Private Class A
		"172.16.0.0/12",  // Private Class B
		"192.168.0.0/16", // Private Class C
		"169.254.0.0/16", // Link-local (includes cloud metadata 169.254.169.254)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}

	blockedCIDRs []*net.IPNet

	blockedHostnames = map[string]bool{
		"localhost":                true,
		"metadata.google.internal": true,
		"metadata.internal":        true,
	}

	// ssrfAllowedHosts is for testing only
	ssrfAllowedHosts   = make(map[string]bool)
	ssrfAllowedHostsMu sync.RWMutex
)

func init() {
	for _, cidr := range blockedIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, network)
		}
	}
}

// AllowSSRFHost temporarily allows a host to bypass SSRF protection (for testing only).
func AllowSSRFHost(host string) func() {
	ssrfAllowedHostsMu.Lock()
	ssrfAllowedHosts[host] = true
	ssrfAllowedHostsMu.Unlock()
	return func() {
		ssrfAllowedHostsMu.Lock()
		delete(ssrfAllowedHosts, host)
		ssrfAllowedHostsMu.Unlock()
	}
}

func validateExternalURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme %q not allowed; only http and https are permitted", parsed.Scheme)
	}

	hostname := parsed.Hostname()

	ssrfAllowedHostsMu.RLock()
	allowed := ssrfAllowedHosts[parsed.Host]
	ssrfAllowedHostsMu.RUnlock()
	if allowed {
		return nil
	}

	if blockedHostnames[strings.ToLower(hostname)] {
		return fmt.Errorf("hostname %q is blocked for security reasons", hostname)
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %q: %w", hostname, err)
	}

	for _, ip := range ips {
		for _, network := range blockedCIDRs {
			if network.Contains(ip) {
				return fmt.Errorf("URL resolves to blocked IP range %s (SSRF protection)", network.String())
			}
		}
	}

	return nil
}

// Regex cache for performance
var (
	regexCache        sync.Map
	regexCacheCount   int64
	regexCacheCountMu sync.Mutex
)

const maxRegexCacheSize = 1000

func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheCountMu.Lock()
	if regexCacheCount >= maxRegexCacheSize {
		regexCache.Range(func(key, _ interface{}) bool {
			regexCache.Delete(key)
			return true
		})
		regexCacheCount = 0
	}
	regexCacheCount++
	regexCacheCountMu.Unlock()

	regexCache.Store(pattern, compiled)
	return compiled, nil
}

func evaluateFieldMatch(fieldValue string, condition *PolicyCondition) bool {
	var conditionValue string
	switch v := condition.Value.(type) {
	case *PolicyCondition_StringValue:
		conditionValue = v.StringValue
	case *PolicyCondition_IntValue:
		conditionValue = strconv.FormatInt(v.IntValue, 10)
	case *PolicyCondition_FloatValue:
		conditionValue = strconv.FormatFloat(v.FloatValue, 'f', -1, 64)
	case *PolicyCondition_BoolValue:
		conditionValue = strconv.FormatBool(v.BoolValue)
	default:
		return false
	}

	switch condition.Operator {
	case ConditionOperator_CONDITION_OPERATOR_EQUALS:
		return fieldValue == conditionValue
	case ConditionOperator_CONDITION_OPERATOR_NOT_EQUALS:
		return fieldValue != conditionValue
	default:
		return false
	}
}

func evaluateRegex(fieldValue string, condition *PolicyCondition) (bool, error) {
	pattern, ok := condition.Value.(*PolicyCondition_StringValue)
	if !ok {
		return false, fmt.Errorf("regex condition requires string value")
	}

	compiled, err := getCompiledRegex(pattern.StringValue)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return compiled.MatchString(fieldValue), nil
}

func evaluateRange(fieldValue string, condition *PolicyCondition) (bool, error) {
	fieldFloat, err := strconv.ParseFloat(fieldValue, 64)
	if err != nil {
		return false, fmt.Errorf("field value is not numeric: %s", fieldValue)
	}

	var conditionFloat float64
	switch v := condition.Value.(type) {
	case *PolicyCondition_IntValue:
		conditionFloat = float64(v.IntValue)
	case *PolicyCondition_FloatValue:
		conditionFloat = v.FloatValue
	default:
		return false, fmt.Errorf("range condition requires numeric value")
	}

	switch condition.Operator {
	case ConditionOperator_CONDITION_OPERATOR_GREATER_THAN:
		return fieldFloat > conditionFloat, nil
	case ConditionOperator_CONDITION_OPERATOR_LESS_THAN:
		return fieldFloat < conditionFloat, nil
	case ConditionOperator_CONDITION_OPERATOR_GREATER_EQUAL:
		return fieldFloat >= conditionFloat, nil
	case ConditionOperator_CONDITION_OPERATOR_LESS_EQUAL:
		return fieldFloat <= conditionFloat, nil
	case ConditionOperator_CONDITION_OPERATOR_EQUALS:
		return fieldFloat == conditionFloat, nil
	case ConditionOperator_CONDITION_OPERATOR_NOT_EQUALS:
		return fieldFloat != conditionFloat, nil
	default:
		return false, fmt.Errorf("unsupported operator for range: %v", condition.Operator)
	}
}

func evaluateInList(fieldValue string, condition *PolicyCondition) bool {
	for _, val := range condition.Values {
		if fieldValue == val {
			return condition.Operator != ConditionOperator_CONDITION_OPERATOR_NOT_IN
		}
	}
	return condition.Operator == ConditionOperator_CONDITION_OPERATOR_NOT_IN
}

func evaluateContains(fieldValue string, condition *PolicyCondition) bool {
	conditionValue, ok := condition.Value.(*PolicyCondition_StringValue)
	if !ok {
		return false
	}
	return strings.Contains(fieldValue, conditionValue.StringValue)
}

func evaluateStartsWith(fieldValue string, condition *PolicyCondition) bool {
	conditionValue, ok := condition.Value.(*PolicyCondition_StringValue)
	if !ok {
		return false
	}
	return strings.HasPrefix(fieldValue, conditionValue.StringValue)
}

func evaluateEndsWith(fieldValue string, condition *PolicyCondition) bool {
	conditionValue, ok := condition.Value.(*PolicyCondition_StringValue)
	if !ok {
		return false
	}
	return strings.HasSuffix(fieldValue, conditionValue.StringValue)
}

func evaluateStatisticalSpike(fieldValue string, condition *PolicyCondition, ctx *EvaluationContext) bool {
	val, err := strconv.ParseFloat(fieldValue, 64)
	if err != nil {
		return false
	}

	avgStr, ok1 := ctx.Attributes[condition.Field+".avg"]
	stddevStr, ok2 := ctx.Attributes[condition.Field+".stddev"]
	if !ok1 || !ok2 {
		return false
	}

	avg, _ := strconv.ParseFloat(avgStr, 64)
	stddev, _ := strconv.ParseFloat(stddevStr, 64)

	if stddev == 0 {
		return false
	}

	zScore := (val - avg) / stddev

	var threshold float64
	switch v := condition.Value.(type) {
	case *PolicyCondition_FloatValue:
		threshold = v.FloatValue
	case *PolicyCondition_IntValue:
		threshold = float64(v.IntValue)
	default:
		threshold = 3.0
	}

	return zScore > threshold
}

func evaluateExternalCall(condition *PolicyCondition, ctx *EvaluationContext) (bool, error) {
	urlValue, ok := condition.Value.(*PolicyCondition_StringValue)
	if !ok {
		return false, fmt.Errorf("external call requires a URL string value")
	}

	if err := validateExternalURL(urlValue.StringValue); err != nil {
		return false, fmt.Errorf("external call blocked: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlValue.StringValue, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create external call request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("external call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("external call returned non-OK status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read external call body: %w", err)
	}

	if condition.Field == "" {
		return true, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return false, fmt.Errorf("failed to parse external call JSON: %w", err)
	}

	val, ok := data[condition.Field]
	if !ok {
		return false, nil
	}

	if b, ok := val.(bool); ok {
		return b, nil
	}

	return true, nil
}
