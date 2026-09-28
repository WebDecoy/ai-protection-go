package aiprotection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetLifecycleAndIndependentFailureMode(t *testing.T) {
	for _, kind := range []string{"complete", "unknown", "model_change", "invalid_usage", "error", "panic", "cancel", "timeout", "deny", "observe", "outage_open", "outage_closed", "settlement_outage", "overrun"} {
		t.Run(kind, func(t *testing.T) {
			var starts, settlements atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/usage") {
					w.WriteHeader(202)
					return
				}
				var p map[string]any
				if e := json.NewDecoder(r.Body).Decode(&p); e != nil {
					t.Error(e)
					return
				}
				if p["subject"] == "private-account" || p["tenant"] == "private-org" {
					t.Error("raw identity")
				}
				if strings.HasPrefix(kind, "outage_") || kind == "settlement_outage" && p["operation"] == "settle" {
					w.WriteHeader(503)
					return
				}
				out := map[string]any{"schema": 1, "allowed": true, "granted": true, "reason": "budget_allowed", "reservation_id": "22222222-2222-4222-8222-222222222222", "retry_after_seconds": 0, "overrun": false}
				if p["operation"] == "reserve" {
					if p["tokens"] != float64(30) || p["micros"] != float64(50) {
						t.Error("reservation", p)
					}
					if kind == "deny" {
						out["allowed"] = false
						out["granted"] = false
						out["reason"] = "budget_exceeded"
						out["retry_after_seconds"] = 7
					}
					if kind == "observe" {
						out["allowed"] = false
						out["reason"] = "budget_exceeded"
					}
				} else {
					settlements.Add(1)
					out["granted"] = false
					out["reason"] = "budget_settled"
					if kind != "overrun" && (p["tokens"] != float64(7) || p["micros"] != float64(11)) {
						t.Error("settlement", p)
					}
				}
				json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			mode, failure := Enforce, Closed
			if kind == "observe" {
				mode = Observe
			}
			if kind == "outage_open" {
				failure = Open
			}
			b := &Budget[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), WindowSeconds: 60, Limits: BudgetLimits{AccountTokens: 100, AccountMicros: 100}, Mode: mode, FailureMode: failure, Prices: map[string]BudgetPrice{"fixture": {Provider: "ollama", Model: "fixture", InputMicrosPerMillion: 1000000, OutputMicrosPerMillion: 2000000}}, Subject: func(s string) BudgetSubject { return BudgetSubject{AccountID: s, OrganizationID: "private-org"} }}
			if kind == "timeout" {
				b.MaxRuntime = 10 * time.Millisecond
			}
			client, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture-key", PropertyID: "11111111-1111-4111-8111-111111111111", Budget: b})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var result BudgetResult
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				result, e = client.RunBudget(ctx, "private-account", BudgetCall{PriceID: "fixture", MaxInputTokens: 10, MaxOutputTokens: 20}, func(ctx context.Context, run BudgetRuntime) (*BudgetUsage, error) {
					starts.Add(1)
					if run.Model != "fixture" || run.MaxOutputTokens != 20 {
						t.Error(run)
					}
					u := &BudgetUsage{Provider: "ollama", Model: "fixture", InputTokens: 3, OutputTokens: 4}
					switch kind {
					case "unknown":
						return nil, nil
					case "model_change":
						u.Model = "other"
					case "invalid_usage":
						u.InputTokens = -1
					case "error":
						return nil, errors.New("provider failed")
					case "panic":
						panic("provider panic")
					case "cancel":
						cancel()
					case "timeout":
						<-ctx.Done()
					case "overrun":
						u.OutputTokens = 21
					}
					return u, nil
				})
			}()
			if kind == "deny" || kind == "outage_closed" {
				if starts.Load() != 0 || result.Allowed || result.Status == 0 {
					t.Fatal(result, starts.Load())
				}
				return
			}
			if starts.Load() != 1 {
				t.Fatal("provider invocation count", starts.Load())
			}
			if kind == "panic" {
				if !panicked {
					t.Fatal("panic swallowed")
				}
				return
			}
			if kind == "error" {
				if e == nil {
					t.Fatal("provider error swallowed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "complete", "observe", "overrun":
				if result.Reason != "budget_settled" || settlements.Load() != 1 {
					t.Fatal(result)
				}
			case "outage_open":
				if result.Reserved || result.Reason != "budget_unavailable" {
					t.Fatal(result)
				}
			case "settlement_outage":
				if result.Reason != "budget_settlement_unavailable" {
					t.Fatal(result)
				}
			default:
				if result.Reason != "budget_usage_unknown" || settlements.Load() != 0 {
					t.Fatal(result)
				}
			}
			if kind == "overrun" && !result.Overrun {
				t.Fatal("overrun hidden")
			}
		})
	}
}
func TestBudgetBoundsPricingAndCancellationBeforeWork(t *testing.T) {
	cost, e := BudgetCost(BudgetPrice{InputMicrosPerMillion: 1, OutputMicrosPerMillion: 1}, 1, 1)
	if e != nil || cost != 1 {
		t.Fatal(cost, e)
	}
	cost, e = BudgetCost(BudgetPrice{InputMicrosPerMillion: 1000000000, OutputMicrosPerMillion: 1000000000}, 10000000, 10000000)
	if e != nil || cost != 20000000000 {
		t.Fatal(cost, e)
	}
	if OllamaBudgetUsage("fixture", true, nil, nil) != nil {
		t.Fatal("missing usage treated as zero")
	}
	zero := int64(0)
	if OllamaBudgetUsage("fixture", true, &zero, &zero) == nil {
		t.Fatal("explicit zero rejected")
	}
	b := &Budget[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), WindowSeconds: 60, Limits: BudgetLimits{AccountTokens: 100}, Prices: map[string]BudgetPrice{"fixture": {Provider: "ollama", Model: "fixture"}}, Subject: func(s string) BudgetSubject { return BudgetSubject{s, "o"} }}
	c, e := New(Config[string]{BaseURL: "https://example.test", APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", Budget: b})
	if e != nil {
		t.Fatal(e)
	}
	never := func(context.Context, BudgetRuntime) (*BudgetUsage, error) {
		t.Fatal("provider started")
		return nil, nil
	}
	if _, e = c.RunBudget(context.Background(), "a", BudgetCall{PriceID: "unknown", MaxInputTokens: 1}, never); e == nil {
		t.Fatal("unknown price accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.RunBudget(ctx, "a", BudgetCall{PriceID: "fixture", MaxInputTokens: 1}, never); e == nil {
		t.Fatal("cancel ignored")
	}
	b.Prices["fixture"] = BudgetPrice{Provider: "bad", Model: "changed"}
	if c.config.Budget.Prices["fixture"].Provider != "ollama" {
		t.Fatal("catalog mutation")
	}
}
