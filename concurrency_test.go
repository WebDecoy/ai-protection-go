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

func TestConcurrencyLifecycle(t *testing.T) {
	for _, kind := range []string{"complete", "error", "panic", "cancel", "denied", "renew_lost", "renew_success", "state_open", "state_closed"} {
		t.Run(kind, func(t *testing.T) {
			var release, renew, starts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var p map[string]any
				json.NewDecoder(r.Body).Decode(&p)
				if p["subject"] == "raw-account" {
					t.Error("raw identity leaked")
				}
				if strings.HasPrefix(kind, "state_") {
					w.WriteHeader(503)
					return
				}
				result := map[string]any{"schema": 1, "allowed": true, "granted": true, "reason": "concurrency_allowed", "lease_id": "22222222-2222-4222-8222-222222222222", "retry_after_seconds": 0, "valid_for_ms": 6000}
				switch p["operation"] {
				case "acquire":
					if kind == "denied" {
						result["allowed"] = false
						result["granted"] = false
						result["reason"] = "concurrency_exceeded"
						result["retry_after_seconds"] = 10
					}
				case "renew":
					renew.Add(1)
					result["reason"] = "concurrency_renewed"
					if kind == "renew_lost" {
						w.WriteHeader(503)
						return
					}
				case "release":
					release.Add(1)
					result["granted"] = false
					result["reason"] = "concurrency_released"
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			failure := Closed
			if kind == "state_open" {
				failure = Open
			}
			client, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", DisableCentralReporting: true, Concurrency: &Concurrency[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), AccountLimit: 1, FeatureLimit: 2, TTLSeconds: 6, MaxSeconds: 12, Mode: Enforce, FailureMode: failure, Subject: func(s string) QuotaSubject { return QuotaSubject{AccountID: s} }}})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			panicked := false
			var d ConcurrencyDecision
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				d, e = client.RunConcurrent(ctx, "raw-account", func(ctx context.Context) error {
					starts.Add(1)
					switch kind {
					case "error":
						return errors.New("uncertain provider")
					case "panic":
						panic("fixture")
					case "cancel":
						cancel()
						return ctx.Err()
					case "renew_lost":
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(4 * time.Second):
							t.Error("lease loss did not cancel work")
						}
					case "renew_success":
						time.Sleep(2300 * time.Millisecond)
					}
					return nil
				})
			}()
			if kind == "denied" || kind == "state_closed" {
				if starts.Load() != 0 || d.Allowed {
					t.Fatal("lost admission invoked provider", d)
				}
				return
			}
			if starts.Load() != 1 {
				t.Fatal("provider starts", starts.Load())
			}
			if kind == "complete" || kind == "renew_success" {
				if e != nil || release.Load() != 1 {
					t.Fatal("confirmed completion", e, release.Load())
				}
			} else if release.Load() != 0 {
				t.Fatal("uncertain work released capacity")
			}
			if strings.HasPrefix(kind, "renew_") && renew.Load() == 0 {
				t.Fatal("no heartbeat")
			}
			if kind == "panic" && !panicked {
				t.Fatal("panic swallowed")
			}
		})
	}
}

func TestProtectConcurrencyPreservesStreamingAndNoPostWorkRetry(t *testing.T) {
	for _, releaseFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "release_partition"}[releaseFails], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var p map[string]any
				json.NewDecoder(r.Body).Decode(&p)
				reason := "concurrency_allowed"
				granted := true
				if p["operation"] == "release" {
					if releaseFails {
						w.WriteHeader(503)
						return
					}
					reason = "concurrency_released"
					granted = false
				}
				json.NewEncoder(w).Encode(map[string]any{"schema": 1, "allowed": true, "granted": granted, "reason": reason, "lease_id": "22222222-2222-4222-8222-222222222222", "retry_after_seconds": 0, "valid_for_ms": 6000})
			}))
			defer server.Close()
			reports := make(chan Report, 1)
			c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture", PropertyID: "11111111-1111-4111-8111-111111111111", DisableCentralReporting: true, OnReport: func(ctx context.Context, r Report) error { reports <- r; return nil }, Concurrency: &Concurrency[string]{RuleID: "chat", SubjectSecret: strings.Repeat("x", 32), AccountLimit: 1, FeatureLimit: 2, TTLSeconds: 6, MaxSeconds: 12, Mode: Enforce, Subject: func(s string) QuotaSubject { return QuotaSubject{AccountID: s} }}})
			if e != nil {
				t.Fatal(e)
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/chat", strings.NewReader("private-body"))
			starts := 0
			e = c.Protect(w, r, Request{Method: "POST", Route: "/chat"}, "account", http.HandlerFunc(func(got http.ResponseWriter, req *http.Request) {
				starts++
				if got != w || req.Body != r.Body {
					t.Fatal("writer/body replaced")
				}
				got.Header().Set("Content-Type", "text/event-stream")
				got.Write([]byte("data: first\n\n"))
				got.(http.Flusher).Flush()
				got.Write([]byte("data: done\n\n"))
			}))
			if e != nil || starts != 1 || !w.Flushed {
				t.Fatal("post-work retry risk", e, starts)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c.Flush(ctx)
			report := <-reports
			if report.Checks[len(report.Checks)-1].ID != "concurrency" {
				t.Fatal("missing concurrency report")
			}
			if releaseFails && report.Action != "handler_error" {
				t.Fatal("release failure not reported", report.Action)
			}
		})
	}
}
