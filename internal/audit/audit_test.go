package audit

import (
	"strings"
	"testing"
	"time"
)

func TestRedactPII(t *testing.T) {
	in := "Contact ada@acme.io with key sk-abcdefghijklmnopqrstuvwxyz and +48 500 100 200"
	out := RedactPII(in)
	if strings.Contains(out, "ada@acme.io") || strings.Contains(out, "sk-abcdef") {
		t.Fatalf("secrets leaked: %s", out)
	}
	if !strings.Contains(out, "[REDACTED_EMAIL]") || !strings.Contains(out, "[REDACTED_SECRET]") {
		t.Fatalf("missing redaction markers: %s", out)
	}
}

func TestEvaluateAllowlistAndBudgets(t *testing.T) {
	cfg := Config{
		ToolAllowlist:   map[string]struct{}{"search": {}, "summarize": {}},
		LatencyBudgetMS: 1500,
		CostBudgetUSD:   0.05,
	}

	ok := Evaluate(cfg, Request{Tools: []string{"search"}, LatencyMS: 200, CostUSD: 0.01})
	if !ok.Allow {
		t.Fatalf("expected allow, got %#v", ok)
	}

	denyTool := Evaluate(cfg, Request{Tools: []string{"shell"}, LatencyMS: 10, CostUSD: 0.01})
	if denyTool.Allow || !strings.Contains(denyTool.Reason, "tool_not_allowlisted") {
		t.Fatalf("expected tool deny, got %#v", denyTool)
	}

	denyLat := Evaluate(cfg, Request{Tools: []string{"search"}, LatencyMS: 2000, CostUSD: 0.01})
	if denyLat.Allow || denyLat.Reason != "latency_budget_exceeded" {
		t.Fatalf("expected latency deny, got %#v", denyLat)
	}

	denyCost := Evaluate(cfg, Request{Tools: []string{"search"}, LatencyMS: 10, CostUSD: 1.0})
	if denyCost.Allow || denyCost.Reason != "cost_budget_exceeded" {
		t.Fatalf("expected cost deny, got %#v", denyCost)
	}
}

func TestBuildLogRedactsPrompt(t *testing.T) {
	cfg := Config{ToolAllowlist: map[string]struct{}{"search": {}}}
	req := Request{
		RequestID: "r1",
		Tools:     []string{"search"},
		Prompt:    "email me at founder@arviser.com",
		CostUSD:   0.01,
		LatencyMS: 100,
	}
	dec := Evaluate(cfg, req)
	event := BuildLog(cfg, req, dec, time.Unix(0, 0).UTC())
	raw, err := MarshalLog(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "founder@arviser.com") {
		t.Fatalf("email present in audit log: %s", raw)
	}
	if !strings.Contains(event.Prompt, "[REDACTED_EMAIL]") {
		t.Fatalf("prompt not redacted: %s", event.Prompt)
	}
}
