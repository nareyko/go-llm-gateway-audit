package audit

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Config gates LLM proxy traffic.
type Config struct {
	ToolAllowlist   map[string]struct{}
	LatencyBudgetMS int64
	CostBudgetUSD   float64
}

// Request is the inbound LLM/tool payload.
type Request struct {
	RequestID string         `json:"request_id"`
	Tools     []string       `json:"tools"`
	Prompt    string         `json:"prompt"`
	CostUSD   float64        `json:"cost_usd"`
	LatencyMS int64          `json:"latency_ms"`
	Meta      map[string]any `json:"meta,omitempty"`
}

// Decision is allow or deny with reason.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// LogEvent is a redacted structured audit record.
type LogEvent struct {
	Timestamp string         `json:"timestamp"`
	RequestID string         `json:"request_id"`
	Allow     bool           `json:"allow"`
	Reason    string         `json:"reason,omitempty"`
	Tools     []string       `json:"tools"`
	Prompt    string         `json:"prompt_redacted"`
	CostUSD   float64        `json:"cost_usd"`
	LatencyMS int64          `json:"latency_ms"`
	Meta      map[string]any `json:"meta,omitempty"`
}

var (
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	keyRe   = regexp.MustCompile(`(?i)\b(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|AKIA[0-9A-Z]{16})\b`)
	phoneRe = regexp.MustCompile(`\b\+?[0-9][0-9\-()\s]{7,}[0-9]\b`)
)

// RedactPII replaces emails, API-looking secrets, and phone-like tokens.
func RedactPII(s string) string {
	out := emailRe.ReplaceAllString(s, "[REDACTED_EMAIL]")
	out = keyRe.ReplaceAllString(out, "[REDACTED_SECRET]")
	out = phoneRe.ReplaceAllString(out, "[REDACTED_PHONE]")
	return out
}

// Evaluate applies allowlist and budget gates.
func Evaluate(cfg Config, req Request) Decision {
	for _, tool := range req.Tools {
		name := strings.TrimSpace(tool)
		if name == "" {
			continue
		}
		if _, ok := cfg.ToolAllowlist[name]; !ok {
			return Decision{Allow: false, Reason: "tool_not_allowlisted:" + name}
		}
	}
	if cfg.LatencyBudgetMS > 0 && req.LatencyMS > cfg.LatencyBudgetMS {
		return Decision{Allow: false, Reason: "latency_budget_exceeded"}
	}
	if cfg.CostBudgetUSD > 0 && req.CostUSD > cfg.CostBudgetUSD {
		return Decision{Allow: false, Reason: "cost_budget_exceeded"}
	}
	return Decision{Allow: true}
}

// BuildLog returns a JSON-serializable redacted event.
func BuildLog(cfg Config, req Request, decision Decision, now time.Time) LogEvent {
	_ = cfg
	meta := map[string]any{}
	for k, v := range req.Meta {
		if s, ok := v.(string); ok {
			meta[k] = RedactPII(s)
		} else {
			meta[k] = v
		}
	}
	return LogEvent{
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		RequestID: req.RequestID,
		Allow:     decision.Allow,
		Reason:    decision.Reason,
		Tools:     append([]string(nil), req.Tools...),
		Prompt:    RedactPII(req.Prompt),
		CostUSD:   req.CostUSD,
		LatencyMS: req.LatencyMS,
		Meta:      meta,
	}
}

// MarshalLog encodes the audit event as one JSON object.
func MarshalLog(event LogEvent) ([]byte, error) {
	return json.Marshal(event)
}
