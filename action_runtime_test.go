package aiprotection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActionRuntimeSharedQuotaAndEvidence(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	reports := []Report{}
	var quotaCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("missing server key")
		}
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/reports") {
			var report Report
			json.NewDecoder(r.Body).Decode(&report)
			reports = append(reports, report)
			w.WriteHeader(202)
			return
		}
		var q struct {
			RuleID  string `json:"rule_id"`
			Subject string `json:"subject"`
			Limit   int    `json:"limit"`
		}
		json.NewDecoder(r.Body).Decode(&q)
		quotaCalls.Add(1)
		key := q.RuleID + q.Subject
		allowed := counts[key] < q.Limit
		if allowed {
			counts[key]++
		}
		reason := "account_quota_allowed"
		retry := 0
		if !allowed {
			reason = "account_quota_exceeded"
			retry = 10
		}
		json.NewEncoder(w).Encode(map[string]any{"schema": 1, "allowed": allowed, "reason": reason, "remaining": max(0, q.Limit-counts[key]), "retry_after_seconds": retry, "reset_at": time.Now().Add(time.Minute).Unix()})
	}))
	defer server.Close()
	var executed atomic.Int32
	makeGuard := func() *ActionProtection[TrustedCaller] {
		p, e := NewActionProtection(ActionOptions[TrustedCaller]{PolicyVersion: "v1", SharedRuntime: &ActionRuntime{BaseURL: server.URL, PropertyID: property, APIKey: "fixture", SubjectSecret: strings.Repeat("x", 32)}, Authenticate: func(_ context.Context, c TrustedCaller) (TrustedCaller, error) { return c, nil }, Actions: map[string]ActionDefinition{"read": {Validate: func(context.Context, json.RawMessage) (bool, error) { return true, nil }, Authorize: func(_ context.Context, c ActionContext) (bool, error) { return string(c.Arguments) != "false", nil }, Execute: func(context.Context, ActionContext) (any, error) { executed.Add(1); return "ok", nil }, Limits: &ActionLimits{CallerQuota: &ActionQuota{RuleID: "caller", Limit: 2, WindowSeconds: 60, Mode: Enforce, FailureMode: Closed}, TenantQuota: &ActionQuota{RuleID: "tenant", Limit: 3, WindowSeconds: 60, Mode: Enforce, FailureMode: Closed}}}}})
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	a, b := makeGuard(), makeGuard()
	ctx := context.Background()
	caller := actionCaller()
	run := func(p *ActionProtection[TrustedCaller], c TrustedCaller, args string, wantStatus int) {
		t.Helper()
		v, e := p.Run(ctx, "read", json.RawMessage(args), c)
		if wantStatus == 0 {
			if e != nil || v != "ok" {
				t.Fatal(v, e)
			}
		} else {
			var d *ActionDenied
			if !errors.As(e, &d) || d.Status != wantStatus {
				t.Fatal(e)
			}
		}
	}
	run(a, caller, "true", 0)
	run(b, caller, "true", 0)
	run(a, caller, "true", 429)
	c := caller
	c.Subject = "other"
	run(a, c, "true", 0)
	c.Subject = "third"
	run(b, c, "true", 429)
	c = caller
	c.Tenant = "tenant-b"
	run(b, c, "true", 0)
	before := quotaCalls.Load()
	run(a, caller, "false", 403)
	if quotaCalls.Load() != before {
		t.Fatal("permission denial consumed quota")
	}
	for _, p := range []*ActionProtection[TrustedCaller]{a, b} {
		if e := p.Flush(ctx); e != nil {
			t.Fatal(e)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if executed.Load() != 4 || len(reports) != 11 {
		t.Fatal(executed.Load(), len(reports))
	}
	events := map[string]bool{}
	actions := map[string]int{}
	for _, r := range reports {
		if r.Schema != 2 || r.ToolAction == nil || !validUUID(r.ToolAction.ActionID) || !validUUID(r.RequestID) || events[r.RequestID] {
			t.Fatal(r)
		}
		events[r.RequestID] = true
		actions[r.ToolAction.ActionID]++
		raw, _ := json.Marshal(r)
		for _, s := range []string{"reader", "tenant-a", "fixture", "\"arguments\""} {
			if strings.Contains(string(raw), s) {
				t.Fatal("private data in event", string(raw))
			}
		}
	}
	if len(actions) != 7 {
		t.Fatal(actions)
	}
}

func TestActionRuntimeFailureAndLeaseLifecycle(t *testing.T) {
	for _, kind := range []string{"quota_open", "quota_closed", "lease_open", "lease_closed", "lease_denied", "release_failed", "cancel", "panic"} {
		t.Run(kind, func(t *testing.T) {
			var starts, releases atomic.Int32
			var mu sync.Mutex
			reports := []Report{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/reports") {
					var v Report
					json.NewDecoder(r.Body).Decode(&v)
					mu.Lock()
					reports = append(reports, v)
					mu.Unlock()
					w.WriteHeader(202)
					return
				}
				if strings.Contains(kind, "open") || strings.Contains(kind, "closed") {
					w.WriteHeader(503)
					return
				}
				var q map[string]any
				json.NewDecoder(r.Body).Decode(&q)
				result := map[string]any{"schema": 1, "allowed": true, "granted": true, "reason": "concurrency_allowed", "lease_id": "22222222-2222-4222-8222-222222222222", "retry_after_seconds": 0, "valid_for_ms": 6000}
				if kind == "lease_denied" {
					result["allowed"] = false
					result["granted"] = false
					result["reason"] = "concurrency_exceeded"
					result["retry_after_seconds"] = 5
				}
				if q["operation"] == "release" {
					releases.Add(1)
					if kind == "release_failed" {
						w.WriteHeader(503)
						return
					}
					result["granted"] = false
					result["reason"] = "concurrency_released"
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mode := Closed
			if strings.HasSuffix(kind, "open") {
				mode = Open
			}
			limits := &ActionLimits{Concurrency: &ActionConcurrency{RuleID: "work", AccountLimit: 1, FeatureLimit: 2, TTLSeconds: 6, MaxSeconds: 12, Mode: Enforce, FailureMode: mode}}
			if strings.HasPrefix(kind, "quota") {
				limits = &ActionLimits{CallerQuota: &ActionQuota{RuleID: "calls", Limit: 1, WindowSeconds: 60, Mode: Enforce, FailureMode: mode}}
			}
			p, e := NewActionProtection(ActionOptions[string]{PolicyVersion: "v1", SharedRuntime: &ActionRuntime{BaseURL: server.URL, PropertyID: property, APIKey: "fixture", SubjectSecret: strings.Repeat("x", 32)}, Authenticate: func(context.Context, string) (TrustedCaller, error) { return actionCaller(), nil }, Actions: map[string]ActionDefinition{"read": {Validate: func(context.Context, json.RawMessage) (bool, error) { return true, nil }, Authorize: func(context.Context, ActionContext) (bool, error) { return true, nil }, Limits: limits, Execute: func(context.Context, ActionContext) (any, error) {
				starts.Add(1)
				if kind == "cancel" {
					cancel()
				}
				if kind == "panic" {
					panic("private execution error")
				}
				return "value", nil
			}}}})
			if e != nil {
				t.Fatal(e)
			}
			var v any
			var runErr error
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				v, runErr = p.Run(ctx, "read", json.RawMessage(`{}`), "")
			}()
			if e := p.Flush(context.Background()); e != nil {
				t.Fatal(e)
			}
			denied := strings.HasSuffix(kind, "closed") || kind == "lease_denied"
			if denied {
				var d *ActionDenied
				if starts.Load() != 0 || !errors.As(runErr, &d) {
					t.Fatal(starts.Load(), runErr)
				}
				if kind == "lease_denied" && d.RetryAfterSeconds != 5 {
					t.Fatal(d)
				}
			} else if starts.Load() != 1 {
				t.Fatal(starts.Load())
			}
			if kind == "release_failed" && (runErr != nil || v != "value" || releases.Load() != 1) {
				t.Fatal(v, runErr, releases.Load())
			}
			if kind == "cancel" && (!errors.Is(runErr, context.Canceled) || releases.Load() != 0) {
				t.Fatal(runErr, releases.Load())
			}
			if kind == "panic" && (!panicked || releases.Load() != 0) {
				t.Fatal(panicked, releases.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			expected := 2
			if denied {
				expected = 1
			}
			if len(reports) != expected {
				t.Fatal(len(reports))
			}
			wantOutcomes := map[string]bool{"attempted": true, "completed": true}
			if denied {
				wantOutcomes = map[string]bool{"not_attempted": true}
			}
			if kind == "cancel" || kind == "panic" {
				wantOutcomes = map[string]bool{"attempted": true, "unknown": true}
			}
			actionID := ""
			for _, report := range reports {
				if report.ToolAction == nil {
					t.Fatal("missing action evidence")
				}
				a := report.ToolAction
				if a.PolicyVersion != "v1" || !wantOutcomes[a.Outcome] {
					t.Fatal(a)
				}
				if actionID != "" && actionID != a.ActionID {
					t.Fatal("uncorrelated phases")
				}
				actionID = a.ActionID
				delete(wantOutcomes, a.Outcome)
			}
			if len(wantOutcomes) != 0 {
				t.Fatal("missing outcomes", wantOutcomes)
			}
			if kind == "release_failed" {
				found := false
				for _, r := range reports {
					if r.ToolAction.Outcome == "completed" {
						found = r.Degraded && r.Checks[len(r.Checks)-1].ID == "concurrency_release"
					}
				}
				if !found {
					t.Fatal(reports)
				}
			}
		})
	}
}

// Vectors generated by the Node SDK's quotaHash with the same framed UTF-8 fields.
func TestActionRuntimeNodeIdentityCompatibility(t *testing.T) {
	runtime, err := prepareActionRuntime(&ActionRuntime{BaseURL: "https://ai-protection.example", APIKey: "fixture", PropertyID: property, SubjectSecret: strings.Repeat("x", 32)}, map[string]ActionDefinition{"read": {Limits: &ActionLimits{CallerQuota: &ActionQuota{RuleID: "caller", Limit: 2, WindowSeconds: 60}, TenantQuota: &ActionQuota{RuleID: "tenant", Limit: 3, WindowSeconds: 60}}}})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"551632d00cc33ad8281c80519eca2310b8d6b41c3b82ad555e1208f7f5563977", "866c3ac072ed1b97002191ac81180f82553e867eb21512b900094a2c9999f8b5"}
	for i, c := range runtime.controls["read"].quotas {
		if got := c.config.AccountQuota.Subject(actionCaller()).AccountID; got != expected[i] {
			t.Fatal(i, got)
		}
	}
}
