package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nareyko/go-llm-gateway-audit/internal/audit"
)

func main() {
	allowFlag := flag.String("allow", "search,summarize", "comma-separated tool allowlist")
	lat := flag.Int64("latency-budget-ms", 1500, "max accepted latency_ms")
	cost := flag.Float64("cost-budget-usd", 0.05, "max accepted cost_usd")
	flag.Parse()

	cfg := audit.Config{
		ToolAllowlist:   map[string]struct{}{},
		LatencyBudgetMS: *lat,
		CostBudgetUSD:   *cost,
	}
	for _, tool := range strings.Split(*allowFlag, ",") {
		tool = strings.TrimSpace(tool)
		if tool != "" {
			cfg.ToolAllowlist[tool] = struct{}{}
		}
	}

	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	denied := false
	for {
		var req audit.Request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "decode error: %v\n", err)
			os.Exit(1)
		}
		decision := audit.Evaluate(cfg, req)
		event := audit.BuildLog(cfg, req, decision, time.Now().UTC())
		if err := enc.Encode(event); err != nil {
			fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
			os.Exit(1)
		}
		if !decision.Allow {
			denied = true
		}
	}
	if denied {
		os.Exit(2)
	}
}
