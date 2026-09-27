// Package aiprotection implements local application policies and remote WebDecoy
// detection. Call it after authentication and validation, before starting inference.
package aiprotection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Mode string

const (
	Observe Mode = "observe"
	Enforce Mode = "enforce"
)

type FailureMode string

const (
	Open   FailureMode = "open"
	Closed FailureMode = "closed"
)

type RuleResult struct {
	Allowed bool
	Reason  string
	Status  int
}
type Rule[T any] struct {
	ID          string
	Mode        Mode                        // Defaults to Observe, independent of cloud mode.
	FailureMode FailureMode                 // Defaults to Closed for enforced rule errors.
	Evaluate    func(T) (RuleResult, error) // Cheap, synchronous; must not perform network I/O.
}
type Config[T any] struct {
	BaseURL, APIKey, PropertyID       string
	Mode                              Mode          // Cloud mode; defaults to Enforce. Start a pilot with Observe.
	DetectorFailureMode               FailureMode   // Defaults to Open.
	DetectorTimeout, ReportingTimeout time.Duration // Each defaults to one second.
	MaxPendingReports                 int           // Defaults to 100.
	AccountQuota                      *AccountQuota[T]
	Rules                             []Rule[T]
	HTTPClient                        *http.Client
	DisableCentralReporting           bool
	OnReport                          func(context.Context, Report) error // Optional local sink; must honor context.
}

// Request contains explicit metadata, never a body. IP must come from trusted
// ingress. Route must be a normalized route such as /protests/{id}/interview/start.
type Request struct {
	IP            netip.Addr
	Method, Route string
	Headers       http.Header
}
type Check struct {
	ID         string  `json:"id"`
	Source     string  `json:"source"`
	Mode       Mode    `json:"mode"`
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	DurationMS float64 `json:"duration_ms"`
}

// Decision is immutable through the public API. Report accepts only decisions
// created by the same client and emits each decision at most once.
type Decision struct {
	report     Report
	status     int
	retryAfter int
	owner      any
	once       sync.Once
}

func (d *Decision) RetryAfterSeconds() int { return d.retryAfter }
func (d *Decision) Allowed() bool          { return d.report.Decision == "allow" }
func (d *Decision) Reason() string         { return d.report.Reason }
func (d *Decision) Status() int            { return d.status }
func (d *Decision) ID() string             { return d.report.RequestID }
func (d *Decision) Degraded() bool         { return d.report.Degraded }
func (d *Decision) Checks() []Check        { return append([]Check(nil), d.report.Checks...) }

type Client[T any] struct {
	config   Config[T]
	http     *http.Client
	now      func() time.Time
	mu       sync.Mutex
	cached   account
	until    time.Time
	pending  chan struct{}
	reportMu sync.Mutex
	inFlight int
	idle     chan struct{}
}

var code = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var uuid = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func validUUID(s string) bool {
	return uuid.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func validMode(m Mode) bool           { return m == Observe || m == Enforce }
func validFailure(m FailureMode) bool { return m == Open || m == Closed }
func New[T any](cfg Config[T]) (*Client[T], error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid WebDecoy origin")
	}
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, errors.New("WebDecoy origin must use HTTPS")
	}
	if !validUUID(cfg.PropertyID) || strings.TrimSpace(cfg.APIKey) == "" || strings.ContainsAny(cfg.APIKey, "\r\n") {
		return nil, errors.New("valid property ID and server API key required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Mode == "" {
		cfg.Mode = Enforce
	}
	if cfg.DetectorFailureMode == "" {
		cfg.DetectorFailureMode = Open
	}
	if cfg.DetectorTimeout == 0 {
		cfg.DetectorTimeout = time.Second
	}
	if cfg.ReportingTimeout == 0 {
		cfg.ReportingTimeout = time.Second
	}
	if cfg.MaxPendingReports == 0 {
		cfg.MaxPendingReports = 100
	}
	if !validMode(cfg.Mode) || !validFailure(cfg.DetectorFailureMode) || cfg.DetectorTimeout < 0 || cfg.ReportingTimeout < 0 || cfg.MaxPendingReports < 1 || len(cfg.Rules) > 32 {
		return nil, errors.New("invalid protection configuration")
	}
	cfg.Rules = append([]Rule[T](nil), cfg.Rules...)
	var quotaErr error
	cfg.AccountQuota, quotaErr = prepareQuota(cfg.AccountQuota)
	if quotaErr != nil {
		return nil, quotaErr
	}
	ids := map[string]bool{"webdecoy": true, "account_quota": true}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Mode == "" {
			r.Mode = Observe
		}
		if r.FailureMode == "" {
			r.FailureMode = Closed
		}
		if !code.MatchString(r.ID) || ids[r.ID] || r.Evaluate == nil || !validMode(r.Mode) || !validFailure(r.FailureMode) {
			return nil, errors.New("invalid or duplicate local rule")
		}
		ids[r.ID] = true
	}
	h := http.Client{}
	if cfg.HTTPClient != nil {
		h = *cfg.HTTPClient
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	idle := make(chan struct{})
	close(idle)
	return &Client[T]{config: cfg, http: &h, now: time.Now, idle: idle}, nil
}
func requestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func evaluate[T any](r Rule[T], trusted T) (value RuleResult, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("local rule panic")
		}
	}()
	value, err = r.Evaluate(trusted)
	if value.Reason == "" {
		if value.Allowed {
			value.Reason = "rule_allowed"
		} else {
			value.Reason = "rule_denied"
		}
	}
	if !code.MatchString(value.Reason) || (value.Status != 0 && value.Status != 403 && value.Status != 429) {
		err = errors.New("invalid local result")
	}
	return
}
func (c *Client[T]) Check(ctx context.Context, req Request, trusted T) (*Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(req.Route, "/") || strings.ContainsAny(req.Route, "?#\r\n") || req.Method == "" {
		return nil, errors.New("method and normalized route required (no query or fragment)")
	}
	id, err := requestID()
	if err != nil {
		return nil, err
	}
	d := &Decision{owner: c, report: Report{Schema: 1, RequestID: id, Timestamp: c.now().UTC(), Decision: "allow", Reason: "allowed", Action: "forwarded", Checks: []Check{}}}
	deny := func(reason string, status int) {
		if d.Allowed() {
			d.report.Decision = "deny"
			d.report.Reason = reason
			d.status = status
			d.report.Action = "denied"
		}
	}
	for _, r := range c.config.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := time.Now()
		value, err := evaluate(r, trusted)
		check := Check{ID: r.ID, Source: "local", Mode: r.Mode, Decision: "allow", Reason: value.Reason, DurationMS: float64(time.Since(start)) / float64(time.Millisecond)}
		if err != nil {
			check.Decision = "unavailable"
			check.Reason = "local_rule_error"
			d.report.Degraded = true
			if r.Mode == Enforce && r.FailureMode == Closed {
				deny("local_rule_error", 503)
			}
		} else if !value.Allowed {
			check.Decision = "deny"
			if r.Mode == Enforce {
				status := value.Status
				if status == 0 {
					status = 403
				}
				deny(value.Reason, status)
			}
		}
		d.report.Checks = append(d.report.Checks, check)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.checkQuota(ctx, trusted, d)
	if err := ctx.Err(); err != nil {
		c.Report(d, Outcome{Cancelled: true})
		return nil, err
	}
	remote := Check{ID: "webdecoy", Source: "remote", Mode: c.config.Mode, Decision: "skipped", Reason: "local_denial"}
	if !d.Allowed() {
		d.report.Checks = append(d.report.Checks, remote)
		return d, nil
	}
	if !req.IP.IsValid() || req.IP.Zone() != "" {
		remote.Reason = "client_ip_unavailable"
		d.report.Degraded = true
		d.report.Checks = append(d.report.Checks, remote)
		return d, nil
	}
	start := time.Now()
	binding := c.binding(ctx)
	remote.Mode = Observe
	if binding.status == "verified" && binding.Enforce != nil && *binding.Enforce && binding.Mode == Enforce {
		remote.Mode = c.config.Mode
	}
	remote.Decision = "unavailable"
	remote.Reason = binding.status
	if binding.status == "verified" {
		decision, err := c.detect(ctx, req, id, remote.Mode)
		if err != nil {
			remote.Reason = "detector_unavailable"
			if remote.Mode == Enforce && c.config.DetectorFailureMode == Closed {
				deny("protection_unavailable", 503)
				d.report.Action = "denied_unavailable"
			}
		} else {
			remote.Decision = decision
			remote.Reason = "detector_" + decision
			if decision == "block" {
				remote.Decision = "deny"
			}
			if remote.Mode == Enforce && decision != "allow" {
				reason := "request_denied"
				if decision == "challenge" {
					reason = "verification_required"
				}
				deny(reason, 403)
			}
		}
	}
	remote.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
	d.report.Checks = append(d.report.Checks, remote)
	if remote.Decision == "unavailable" {
		d.report.Degraded = true
	}
	if err := ctx.Err(); err != nil {
		c.Report(d, Outcome{Cancelled: true})
		return nil, err
	}
	return d, nil
}

// Protect invokes next only after admission. Use inside an authenticated route,
// before writing SSE headers. The original writer and request reach next unchanged.
func (c *Client[T]) Protect(w http.ResponseWriter, r *http.Request, req Request, trusted T, next http.Handler) error {
	d, err := c.Check(r.Context(), req, trusted)
	if err != nil {
		return err
	}
	outcome := Outcome{}
	defer func() {
		if value := recover(); value != nil {
			outcome.HandlerError = true
			c.Report(d, outcome)
			panic(value)
		}
		outcome.Cancelled = r.Context().Err() != nil
		c.Report(d, outcome)
	}()
	if err = r.Context().Err(); err != nil {
		return err
	}
	if !d.Allowed() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-WebDecoy-Request-ID", d.ID())
		if d.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(d.retryAfter))
		}
		w.WriteHeader(d.Status())
		fmt.Fprintf(w, `{"error":%q,"request_id":%q}`, d.Reason(), d.ID())
		return nil
	}
	outcome.HandlerAttempted = true
	next.ServeHTTP(w, r)
	return nil
}
