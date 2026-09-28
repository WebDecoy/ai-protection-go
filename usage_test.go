package aiprotection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestUsageReportsDoNotChangeProviderResult(t *testing.T) {
	var mu sync.Mutex
	var events []UsageReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/usage") {
			var event UsageReport
			if e := json.NewDecoder(r.Body).Decode(&event); e != nil {
				t.Error(e)
			}
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
			w.WriteHeader(503)
			return
		}
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		grant := p["operation"] == "reserve"
		reason := "budget_settled"
		if grant {
			reason = "budget_allowed"
		}
		json.NewEncoder(w).Encode(map[string]any{"schema": 1, "allowed": true, "granted": grant, "reason": reason, "reservation_id": "22222222-2222-4222-8222-222222222222", "retry_after_seconds": 0, "overrun": false})
	}))
	defer server.Close()
	c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", Budget: &Budget[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), WindowSeconds: 60, Limits: BudgetLimits{AccountTokens: 100}, Prices: map[string]BudgetPrice{"fixture": {Provider: "ollama", Model: "private-model", InputMicrosPerMillion: 1000000, OutputMicrosPerMillion: 2000000}}, Subject: func(string) BudgetSubject {
		return BudgetSubject{AccountID: "private-account", OrganizationID: "private-org"}
	}}})
	if e != nil {
		t.Fatal(e)
	}
	starts := 0
	req := "33333333-3333-4333-8333-333333333333"
	for i := 0; i < 2; i++ {
		r, e := c.RunBudget(context.Background(), "private-prompt", BudgetCall{RequestID: req, PriceID: "fixture", MaxInputTokens: 10, MaxOutputTokens: 20}, func(context.Context, BudgetRuntime) (*BudgetUsage, error) {
			starts++
			return &BudgetUsage{Provider: "ollama", Model: "private-model", InputTokens: 3, OutputTokens: 4}, nil
		})
		if e != nil || r.Reason != "budget_settled" {
			t.Fatal(r, e)
		}
	}
	if e = c.Flush(context.Background()); e != nil {
		t.Fatal(e)
	}
	if starts != 2 {
		t.Fatal(starts)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 4 {
		t.Fatal(events)
	}
	calls := map[string]int{}
	for _, event := range events {
		calls[event.CallID]++
		if event.RequestID != req || !event.Started {
			t.Fatal(event)
		}
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), "private-") {
			t.Fatal("private context leaked")
		}
		if event.Phase == "finish" && (event.CostMicros == nil || *event.CostMicros != 11) {
			t.Fatal(event)
		}
	}
	if len(calls) != 2 {
		t.Fatal(calls)
	}
}
