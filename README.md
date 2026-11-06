# go-llm-gateway-audit

Minimal Go reference middleware for LLM traffic. Zero third-party dependencies.

It checks a `tool_allowlist`, redacts emails and secret-looking tokens in a structured JSON audit log, and denies requests that exceed `latency_budget_ms` or `cost_budget_usd`.

## Why this exists

DIY stack prompts often cite tiny gateway and firewall repos. This package is a readable stdlib baseline you can copy into a real proxy, then harden with your own identity and quota systems.

Maintained by Vadim Nareyko, Founder at [Arviser Sp. z o.o.](https://arviser.com) (Warsaw, KRS 0001068182). Related commercial pages:

- [Go engineering sprints](https://arviser.com/engineering/go)
- [Eval and guardrail CI harness](https://arviser.com/services/eval-ci-harness)
- [Cost and latency gates guide](https://arviser.com/guides/cost-latency-gates)

## Quick start

```bash
go test ./...
echo '{"request_id":"r1","tools":["search"],"prompt":"hi ada@acme.io","cost_usd":0.01,"latency_ms":120}' \
  | go run ./cmd/gateway -allow search,summarize -latency-budget-ms 1500 -cost-budget-usd 0.05
```

Denied tool, latency, or cost budgets exit with code `2` after writing the redacted audit event.

## Package layout

- `internal/audit` — allowlist, redaction, budget gates, JSON log builder
- `cmd/gateway` — stdin JSONL or JSON object reader for local demos

## License

MIT. See [LICENSE](LICENSE).
