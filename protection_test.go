package aiprotection

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const property = "11111111-1111-4111-8111-111111111111"

type trusted struct {
	Plan   string
	Secret string
}
type fixture struct {
	mu                         sync.Mutex
	decision                   string
	mode                       Mode
	detectStatus, reportStatus int
	mismatch                   bool
	configs, detects           int
	payload                    []byte
	reports                    []Report
	onDetect                   func()
}

func setup(t *testing.T) (*fixture, Config[trusted]) {
	t.Helper()
	f := &fixture{decision: "allow", mode: Enforce, detectStatus: 200, reportStatus: 202}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer fixture" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/sdk/ai-abuse/config":
			f.configs++
			p := property
			if f.mismatch {
				p = "33333333-3333-4333-8333-333333333333"
			}
			json.NewEncoder(w).Encode(map[string]any{"schema": 1, "property_id": p, "organization_id": "22222222-2222-4222-8222-222222222222", "observe": true, "enforce": true, "mode": f.mode})
		case "/api/v1/sdk/detect":
			f.detects++
			f.payload, _ = io.ReadAll(r.Body)
			if f.onDetect != nil {
				f.onDetect()
			}
			w.WriteHeader(f.detectStatus)
			json.NewEncoder(w).Encode(map[string]any{"decision_mode": "unified_v1", "decision": f.decision})
		case "/api/v1/sdk/ai-abuse/reports":
			if r.Header.Get("X-WebDecoy-Property-ID") != property {
				w.WriteHeader(403)
				return
			}
			var report Report
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&report) != nil {
				w.WriteHeader(400)
				return
			}
			f.reports = append(f.reports, report)
			w.WriteHeader(f.reportStatus)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	return f, Config[trusted]{BaseURL: server.URL, APIKey: "fixture", PropertyID: property}
}
func metadata() Request {
	return Request{IP: netip.MustParseAddr("192.0.2.1"), Method: "POST", Route: "/protests/{id}/interview/respond", Headers: http.Header{"Authorization": []string{"private-auth"}, "Cookie": []string{"private-cookie"}}}
}
func newClient(t *testing.T, cfg Config[trusted]) *Client[trusted] {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func flush(t *testing.T, c *Client[trusted]) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestLocalRulesPrivacyAndReporting(t *testing.T) {
	f, cfg := setup(t)
	cfg.Rules = []Rule[trusted]{{ID: "plan", Mode: Enforce, Evaluate: func(c trusted) (RuleResult, error) {
		return RuleResult{Allowed: c.Plan == "paid", Reason: "paid_required"}, nil
	}}}
	c := newClient(t, cfg)
	d, err := c.Check(context.Background(), metadata(), trusted{Plan: "free", Secret: "private-context"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() || d.Status() != 403 || d.Checks()[1].Decision != "skipped" {
		t.Fatal(d)
	}
	checks := d.Checks()
	checks[0].Reason = "mutation"
	if d.Checks()[0].Reason == "mutation" {
		t.Fatal("mutable decision")
	}
	if !c.Report(d, Outcome{}) || c.Report(d, Outcome{}) {
		t.Fatal("report dedup failed")
	}
	flush(t, c)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.detects != 0 || f.configs != 0 || len(f.reports) != 1 {
		t.Fatal(f.detects, f.configs, len(f.reports))
	}
	raw, _ := json.Marshal(f.reports)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("secret leaked")
	}
	if f.reports[0].Decision != "deny" || !validUUID(f.reports[0].RequestID) {
		t.Fatal(f.reports)
	}
}
func TestRemoteModesOutagesAndMetadata(t *testing.T) {
	f, cfg := setup(t)
	c := newClient(t, cfg)
	for _, verdict := range []string{"block", "challenge"} {
		f.mu.Lock()
		f.decision = verdict
		f.mu.Unlock()
		d, err := c.Check(context.Background(), metadata(), trusted{Secret: "private-context"})
		if err != nil || d.Allowed() || d.Status() != 403 {
			t.Fatal(d, err)
		}
	}
	cfg.Mode = Observe
	observe := newClient(t, cfg)
	d, err := observe.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() {
		t.Fatal(d, err)
	}
	f.mu.Lock()
	f.detectStatus = 503
	f.mu.Unlock()
	d, err = c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() {
		t.Fatal(d, err)
	}
	cfg.Mode = Enforce
	cfg.DetectorFailureMode = Closed
	closed := newClient(t, cfg)
	d, err = closed.Check(context.Background(), metadata(), trusted{})
	if err != nil || d.Status() != 503 {
		t.Fatal(d, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, secret := range []string{"private-auth", "private-cookie", "private-context"} {
		if strings.Contains(string(f.payload), secret) {
			t.Fatal("leak", secret)
		}
	}
	if !strings.Contains(string(f.payload), `/protests/{id}/interview/respond`) {
		t.Fatal(string(f.payload))
	}
}
func TestBindingMismatchAndMissingIPFailOpen(t *testing.T) {
	f, cfg := setup(t)
	cfg.DetectorFailureMode = Closed
	f.mismatch = true
	c := newClient(t, cfg)
	d, err := c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() || d.Checks()[0].Reason != "property_mismatch" {
		t.Fatal(d, err)
	}
	req := metadata()
	req.IP = netip.Addr{}
	d, err = c.Check(context.Background(), req, trusted{})
	if err != nil || !d.Allowed() || d.Checks()[0].Reason != "client_ip_unavailable" {
		t.Fatal(d, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.detects != 0 {
		t.Fatal(f.detects)
	}
}
func TestLocalFailuresAreIndependent(t *testing.T) {
	_, cfg := setup(t)
	for _, failure := range []FailureMode{Closed, Open} {
		cfg.Rules = []Rule[trusted]{{ID: "policy", Mode: Enforce, FailureMode: failure, Evaluate: func(trusted) (RuleResult, error) { panic("private-error") }}}
		c := newClient(t, cfg)
		d, err := c.Check(context.Background(), metadata(), trusted{})
		if err != nil || !d.Degraded() || (d.Allowed() != (failure == Open)) {
			t.Fatal(d, err)
		}
		if strings.Contains(d.Reason(), "private") {
			t.Fatal(d)
		}
	}
}
func TestCancellationNeverStartsHandler(t *testing.T) {
	f, cfg := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onDetect = cancel
	c := newClient(t, cfg)
	r := httptest.NewRequest("POST", "/interview", nil).WithContext(ctx)
	called := false
	err := c.Protect(httptest.NewRecorder(), r, metadata(), trusted{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal(err, called)
	}
	flush(t, c)
}
func TestWrapperPreservesWriterStreamingAndBody(t *testing.T) {
	_, cfg := setup(t)
	c := newClient(t, cfg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/interview", strings.NewReader("private-prompt"))
	err := c.Protect(w, r, metadata(), trusted{}, http.HandlerFunc(func(actual http.ResponseWriter, request *http.Request) {
		if actual != w || request != r {
			t.Fatal("wrapped original objects")
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != "private-prompt" {
			t.Fatal(string(body))
		}
		actual.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(actual, "data: hello\n\n")
		actual.(http.Flusher).Flush()
	}))
	if err != nil || !w.Flushed || !strings.Contains(w.Body.String(), "hello") {
		t.Fatal(err, w)
	}
	flush(t, c)
}
func TestReportingBoundsAndIndependentSinks(t *testing.T) {
	f, cfg := setup(t)
	cfg.MaxPendingReports = 1
	cfg.ReportingTimeout = 20 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	cfg.OnReport = func(ctx context.Context, r Report) error {
		close(started)
		<-release
		return errors.New("private-sink")
	}
	c := newClient(t, cfg)
	req := metadata()
	req.IP = netip.Addr{}
	d, _ := c.Check(context.Background(), req, trusted{})
	if !c.Report(d, Outcome{}) {
		t.Fatal("not queued")
	}
	<-started
	second, _ := c.Check(context.Background(), req, trusted{})
	if c.Report(second, Outcome{}) {
		t.Fatal("queue exceeded")
	}
	timeout, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if !errors.Is(c.Flush(timeout), context.DeadlineExceeded) {
		t.Fatal("unbounded flush")
	}
	close(release)
	flush(t, c)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) != 1 {
		t.Fatal("sink blocked central report")
	}
}
func TestConcurrentCacheAndReports(t *testing.T) {
	f, cfg := setup(t)
	c := newClient(t, cfg)
	var wg sync.WaitGroup
	var failed atomic.Bool
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := c.Check(context.Background(), metadata(), trusted{})
			if err != nil || !d.Allowed() {
				failed.Store(true)
				return
			}
			c.Report(d, Outcome{HandlerAttempted: true})
		}()
	}
	wg.Wait()
	flush(t, c)
	f.mu.Lock()
	defer f.mu.Unlock()
	if failed.Load() || f.configs != 1 || f.detects != 20 || len(f.reports) != 20 {
		t.Fatal(f.configs, f.detects, len(f.reports))
	}
}
func TestExpiredAccountGrantNotReused(t *testing.T) {
	f, cfg := setup(t)
	c := newClient(t, cfg)
	now := time.Now()
	c.now = func() time.Time { return now }
	f.decision = "block"
	first, _ := c.Check(context.Background(), metadata(), trusted{})
	if first.Allowed() {
		t.Fatal("expected initial denial")
	}
	f.mu.Lock()
	f.mismatch = true
	f.mu.Unlock()
	now = now.Add(61 * time.Second)
	d, err := c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() {
		t.Fatal(d, err)
	}
}

func TestDetectorTimeoutFailsOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			json.NewEncoder(w).Encode(map[string]any{"schema": 1, "property_id": property, "organization_id": "22222222-2222-4222-8222-222222222222", "mode": "enforce", "observe": true, "enforce": true})
			return
		}
		io.Copy(io.Discard, r.Body) // Drain request so net/http can observe the client disconnect.
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	c := newClient(t, Config[trusted]{BaseURL: server.URL, APIKey: "fixture", PropertyID: property, DetectorTimeout: 20 * time.Millisecond})
	d, err := c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() || d.Checks()[0].Reason != "detector_unavailable" {
		t.Fatal(d, err)
	}
}
func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer server.Close()
	c := newClient(t, Config[trusted]{BaseURL: server.URL, APIKey: "fixture", PropertyID: property})
	d, err := c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() || hits.Load() != 0 {
		t.Fatal(d, err, hits.Load())
	}
}
func TestMalformedBindingCannotAuthorizeScoring(t *testing.T) {
	var scored atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			json.NewEncoder(w).Encode(map[string]any{"schema": 1, "property_id": property, "organization_id": "22222222-2222-4222-8222-222222222222", "mode": "enforce", "observe": true})
			return
		}
		scored.Store(true)
	}))
	defer server.Close()
	c := newClient(t, Config[trusted]{BaseURL: server.URL, APIKey: "fixture", PropertyID: property})
	d, err := c.Check(context.Background(), metadata(), trusted{})
	if err != nil || !d.Allowed() || !d.Degraded() || scored.Load() {
		t.Fatal(d, err, scored.Load())
	}
}
