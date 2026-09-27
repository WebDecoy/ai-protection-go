package aiprotection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountQuotaModePrivacyAndFailures(t *testing.T) {
	for _, mode := range []Mode{Observe, Enforce} {
		for _, failure := range []FailureMode{Open, Closed} {
			for _, outage := range []bool{false, true} {
				t.Run(string(mode)+"/"+string(failure)+"/outage="+map[bool]string{false: "false", true: "true"}[outage], func(t *testing.T) {
					var calls atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						if r.URL.Path != "/api/v1/sdk/ai-abuse/quota" {
							t.Error("quota denial must skip detector", r.URL.Path)
							w.WriteHeader(404)
							return
						}
						var body map[string]any
						json.NewDecoder(r.Body).Decode(&body)
						raw, _ := json.Marshal(body)
						if strings.Contains(string(raw), "sensitive-account") || strings.Contains(string(raw), "prompt-secret") || body["subject"] != quotaHash(strings.Repeat("x", 32), "webdecoy.account-quota.v1", "11111111-1111-4111-8111-111111111111", "chat_v1", "account", "sensitive-account") {
							t.Error("subject privacy", string(raw))
						}
						if outage {
							w.WriteHeader(503)
							return
						}
						w.Write([]byte(`{"schema":1,"allowed":false,"reason":"account_quota_exceeded","remaining":0,"retry_after_seconds":30,"reset_at":2000000000}`))
					}))
					defer server.Close()
					c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", Mode: Observe, DisableCentralReporting: true, AccountQuota: &AccountQuota[string]{RuleID: "chat_v1", SubjectSecret: strings.Repeat("x", 32), Limit: 2, WindowSeconds: 60, Mode: mode, FailureMode: failure, Subject: func(s string) QuotaSubject { return QuotaSubject{AccountID: s} }}})
					if e != nil {
						t.Fatal(e)
					}
					r := httptest.NewRequest("POST", "/chat", strings.NewReader("prompt-secret"))
					r.Header.Set("X-Account-ID", "attacker-controlled")
					w := httptest.NewRecorder()
					invoked := false
					e = c.Protect(w, r, Request{Method: "POST", Route: "/chat"}, "sensitive-account", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { invoked = true; w.WriteHeader(200) }))
					if e != nil {
						t.Fatal(e)
					}
					deny := mode == Enforce && (!outage || failure == Closed)
					if invoked == deny || calls.Load() != 1 {
						t.Fatal("admission", invoked, calls.Load())
					}
					if deny && !outage && (w.Code != 429 || w.Header().Get("Retry-After") != "30") {
						t.Fatal("retry", w.Code, w.Header())
					}
					if deny && outage && w.Code != 503 {
						t.Fatal(w.Code)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					c.Flush(ctx)
				})
			}
		}
	}
}
func TestAccountQuotaCancellationAndInvalidSubject(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{"schema":1}`)) }))
	defer server.Close()
	q := &AccountQuota[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), Limit: 1, WindowSeconds: 60, Mode: Enforce, FailureMode: Closed, Subject: func(s string) QuotaSubject { return QuotaSubject{AccountID: s} }}
	c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", AccountQuota: q})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Check(ctx, Request{Method: "POST", Route: "/chat"}, "account"); e == nil || calls.Load() != 0 {
		t.Fatal("cancelled call dispatched")
	}
	d, e := c.Check(context.Background(), Request{Method: "POST", Route: "/chat"}, "")
	if e != nil || d.Allowed() || calls.Load() != 0 {
		t.Fatal("invalid subject")
	}
	d, e = c.Check(context.Background(), Request{Method: "POST", Route: "/chat"}, "account")
	if e != nil || d.Allowed() || d.Reason() != "account_quota_unavailable" {
		t.Fatal("malformed response accepted")
	}
	// Configuration is copied: changing the caller's struct cannot increase quota.
	q.Limit = 9000
	if c.config.AccountQuota.Limit != 1 {
		t.Fatal("mutable quota config")
	}
}

func TestAccountQuotaTimeoutAndInFlightCancellation(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		t.Run(map[bool]string{false: "state_timeout_open", true: "caller_cancellation"}[cancelCaller], func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				close(started)
				select {
				case <-r.Context().Done():
				case <-time.After(100 * time.Millisecond):
				}
			}))
			defer server.Close()
			c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", DisableCentralReporting: true, AccountQuota: &AccountQuota[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), Limit: 1, WindowSeconds: 60, Mode: Enforce, FailureMode: Open, Timeout: 20 * time.Millisecond, Subject: func(s string) QuotaSubject { return QuotaSubject{AccountID: s} }}})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelCaller {
				go func() { <-started; cancel() }()
			}
			r := httptest.NewRequest("POST", "/chat", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			called := false
			e = c.Protect(w, r, Request{Method: "POST", Route: "/chat"}, "account", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			if cancelCaller {
				if e == nil || called {
					t.Fatal("cancelled caller invoked handler")
				}
			} else if e != nil || !called {
				t.Fatal("quota timeout did not fail open", e)
			}
			drain, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			c.Flush(drain)
		})
	}
}
