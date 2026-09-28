package aiprotection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReleaseTransportBoundsAndCancellation(t *testing.T) {
	for _, part := range []string{"config", "detect"} {
		for _, kind := range []string{"oversized", "malformed", "stall", "redirect"} {
			t.Run(part+"_"+kind, func(t *testing.T) {
				var destinationCalls atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
				defer target.Close()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/"+part) {
						switch kind {
						case "oversized":
							w.Write([]byte(strings.Repeat(" ", 65537) + "{}"))
						case "malformed":
							w.Write([]byte("{bad"))
						case "stall":
							w.Write([]byte("{"))
							w.(http.Flusher).Flush()
							<-r.Context().Done()
						case "redirect":
							http.Redirect(w, r, target.URL, http.StatusFound)
						}
						return
					}
					if strings.HasSuffix(r.URL.Path, "/config") {
						json.NewEncoder(w).Encode(map[string]any{"schema": 1, "property_id": property, "organization_id": "22222222-2222-4222-8222-222222222222", "mode": "enforce", "observe": true, "enforce": true})
					} else {
						json.NewEncoder(w).Encode(map[string]any{"decision_mode": "unified_v1", "decision": "allow"})
					}
				}))
				defer server.Close()
				c, e := New(Config[string]{BaseURL: server.URL, APIKey: "fixture-secret", PropertyID: property, DetectorTimeout: 35 * time.Millisecond, DisableCentralReporting: true})
				if e != nil {
					t.Fatal(e)
				}
				before := time.Now()
				d, e := c.Check(context.Background(), Request{IP: netip.MustParseAddr("192.0.2.1"), Route: "/users/{id}/chat", Method: "POST"}, "")
				if e != nil || !d.Allowed() || !d.Degraded() || time.Since(before) > 700*time.Millisecond || destinationCalls.Load() != 0 {
					t.Fatal(d, e, time.Since(before), destinationCalls.Load())
				}
			})
		}
	}
}
func TestReleaseLimitsRejectUnboundedConfiguration(t *testing.T) {
	_, cfg := setup(t)
	for _, mutate := range []func(*Config[trusted]){func(c *Config[trusted]) { c.DetectorTimeout = 11 * time.Second }, func(c *Config[trusted]) { c.ReportingTimeout = 11 * time.Second }, func(c *Config[trusted]) { c.MaxPendingReports = 10001 }} {
		v := cfg
		mutate(&v)
		if _, e := New(v); e == nil {
			t.Fatal("unbounded config accepted")
		}
	}
}
