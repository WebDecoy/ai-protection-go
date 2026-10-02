package aiprotection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// TrustedCaller is supplied by verified application authentication, never tool arguments.
// Issuer/client are not verified agent identity or proof of delegation.
type TrustedCaller struct {
	Schema                                                  int
	Subject, Tenant, Issuer, AuthenticationMethod, ClientID string
	ExpiresAt                                               time.Time
	Scopes                                                  []string
}
type ActionContext struct {
	Caller    TrustedCaller
	Arguments json.RawMessage
}
type ActionDefinition struct {
	Limits         *ActionLimits
	RequiredScopes []string
	Validate       func(context.Context, json.RawMessage) (bool, error)
	Authorize      func(context.Context, ActionContext) (bool, error)
	Policy         func(context.Context, ActionContext) (bool, error)
	// Execute must await all work; this preview does not own live stream completion.
	Execute func(context.Context, ActionContext) (any, error)
}
type ActionEvent struct {
	EventID       string    `json:"eventId"`
	Timestamp     time.Time `json:"timestamp"`
	Checks        []Check   `json:"checks"`
	Schema        int       `json:"schema"`
	ActionID      string    `json:"actionId"`
	Action        string    `json:"action"`
	PolicyVersion string    `json:"policyVersion"`
	Evaluation    string    `json:"evaluation"`
	Decision      string    `json:"decision"`
	Reason        string    `json:"reason"`
	Attempted     bool      `json:"attempted"`
	Outcome       string    `json:"outcome"`
}
type ActionDenied struct {
	RetryAfterSeconds int
	Reason            string
	Status            int
	ActionID          string
}

func (e *ActionDenied) Error() string { return e.Reason }

type ActionOptions[T any] struct {
	SharedRuntime    *ActionRuntime
	PolicyVersion    string
	Authenticate     func(context.Context, T) (TrustedCaller, error)
	Actions          map[string]ActionDefinition
	AdmissionTimeout time.Duration
	OnEvent          func(ActionEvent)
}
type ActionProtection[T any] struct {
	runtime    *preparedActionRuntime
	options    ActionOptions[T]
	admissions chan struct{}
	observers  chan struct{}
}

var actionName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$`)

func actionString(s string) bool {
	return len(s) > 0 && len(s) <= 512 && !strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
}
func NewActionProtection[T any](o ActionOptions[T]) (*ActionProtection[T], error) {
	if o.Authenticate == nil || !actionName.MatchString(o.PolicyVersion) || len(o.Actions) == 0 || len(o.Actions) > 128 {
		return nil, errors.New("invalid action configuration")
	}
	if o.AdmissionTimeout == 0 {
		o.AdmissionTimeout = time.Second
	}
	if o.AdmissionTimeout < time.Millisecond || o.AdmissionTimeout > 10*time.Second {
		return nil, errors.New("invalid admission timeout")
	}
	definitions := make(map[string]ActionDefinition, len(o.Actions))
	for name, d := range o.Actions {
		if !actionName.MatchString(name) || d.Validate == nil || d.Authorize == nil || d.Execute == nil || len(d.RequiredScopes) > 64 {
			return nil, errors.New("invalid action definition")
		}
		for _, s := range d.RequiredScopes {
			if !actionString(s) {
				return nil, errors.New("invalid scope")
			}
		}
		d.RequiredScopes = slices.Clone(d.RequiredScopes)
		definitions[name] = d
	}
	o.Actions = definitions
	runtime, err := prepareActionRuntime(o.SharedRuntime, definitions)
	if err != nil {
		return nil, err
	}
	return &ActionProtection[T]{runtime: runtime, options: o, admissions: make(chan struct{}, 32), observers: make(chan struct{}, 100)}, nil
}
func copyActionContext(c ActionContext) ActionContext {
	c.Caller.Scopes = slices.Clone(c.Caller.Scopes)
	c.Arguments = bytes.Clone(c.Arguments)
	return c
}
func validCaller(c TrustedCaller) bool {
	if c.Schema != 1 || !actionString(c.Subject) || !actionString(c.Tenant) || !actionString(c.Issuer) || !actionString(c.AuthenticationMethod) || !c.ExpiresAt.After(time.Now()) || len(c.Scopes) > 64 || (c.ClientID != "" && !actionString(c.ClientID)) {
		return false
	}
	for _, s := range c.Scopes {
		if !actionString(s) {
			return false
		}
	}
	return true
}

// Token-level parsing rejects duplicate keys instead of allowing parsers to disagree.
func actionJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 16384 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var walk func(int) bool
	walk = func(depth int) bool {
		nodes++
		if nodes > 2048 || depth > 12 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		if n, ok := t.(json.Number); ok {
			if _, err := strconv.ParseFloat(string(n), 64); err != nil {
				return false
			}
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return false
			}
			keys := map[string]bool{}
			for d.More() {
				if delim == '{' {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || len(s) > 512 || keys[s] || s == "__proto__" || s == "constructor" || s == "prototype" {
						return false
					}
					keys[s] = true
				}
				if !walk(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
		}
		return true
	}
	if !walk(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func (p *ActionProtection[T]) emit(e ActionEvent) {
	e.EventID, _ = requestID()
	e.Timestamp = time.Now().UTC()
	e.Checks = slices.Clone(e.Checks)
	if p.runtime != nil {
		p.runtime.report(e)
	}
	if p.options.OnEvent == nil {
		return
	}
	select {
	case p.observers <- struct{}{}:
	default:
		return
	}
	go func() { defer func() { <-p.observers; _ = recover() }(); p.options.OnEvent(e) }()
}

type actionAdmission struct {
	context ActionContext
	reason  string
	status  int
}

func (p *ActionProtection[T]) admit(ctx context.Context, d ActionDefinition, args []byte, auth T) (r actionAdmission) {
	defer func() {
		if recover() != nil {
			r = actionAdmission{reason: "authorization_unavailable", status: 503}
		}
	}()
	c, e := p.options.Authenticate(ctx, auth)
	if e != nil || !validCaller(c) {
		return actionAdmission{reason: "authentication_required", status: 401}
	}
	ac := copyActionContext(ActionContext{Caller: c, Arguments: args})
	for _, s := range d.RequiredScopes {
		if !slices.Contains(ac.Caller.Scopes, s) {
			return actionAdmission{reason: "missing_scope", status: 403}
		}
	}
	if ctx.Err() != nil {
		return actionAdmission{reason: "admission_timeout", status: 503}
	}
	ok, e := d.Validate(ctx, bytes.Clone(args))
	if e != nil || !ok {
		return actionAdmission{reason: "invalid_arguments", status: 400}
	}
	if ctx.Err() != nil {
		return actionAdmission{reason: "admission_timeout", status: 503}
	}
	ok, e = d.Authorize(ctx, copyActionContext(ac))
	if e != nil {
		return actionAdmission{reason: "authorization_unavailable", status: 503}
	}
	if !ok {
		return actionAdmission{reason: "permission_denied", status: 403}
	}
	if ctx.Err() != nil {
		return actionAdmission{reason: "admission_timeout", status: 503}
	}
	if d.Policy != nil {
		ok, e = d.Policy(ctx, copyActionContext(ac))
		if e != nil {
			return actionAdmission{reason: "policy_unavailable", status: 503}
		}
		if !ok {
			return actionAdmission{reason: "policy_denied", status: 403}
		}
	}
	return actionAdmission{context: ac}
}
func (p *ActionProtection[T]) Run(ctx context.Context, name string, args json.RawMessage, auth T) (value any, err error) {
	id, err := requestID()
	if err != nil {
		return nil, err
	}
	d, known := p.options.Actions[name]
	eventName := name
	if !known {
		eventName = "unregistered"
	}
	attempted := false
	checks := []Check{}
	retry := 0
	emit := func(decision, reason, outcome string) {
		p.emit(ActionEvent{Schema: 1, ActionID: id, Action: eventName, PolicyVersion: p.options.PolicyVersion, Evaluation: "local", Decision: decision, Reason: reason, Attempted: attempted, Outcome: outcome, Checks: checks})
	}
	deny := func(reason string, status int) (any, error) {
		emit("deny", reason, "not_attempted")
		return nil, &ActionDenied{Reason: reason, Status: status, ActionID: id, RetryAfterSeconds: retry}
	}
	if err = ctx.Err(); err != nil {
		emit("deny", "admission_cancelled", "not_attempted")
		return nil, err
	}
	if !known {
		return deny("action_not_registered", 403)
	}
	snapshot := bytes.Clone(args)
	if !actionJSON(snapshot) {
		return deny("invalid_arguments", 400)
	}
	select {
	case p.admissions <- struct{}{}:
	default:
		return deny("admission_unavailable", 503)
	}
	admissionCtx, cancel := context.WithTimeout(ctx, p.options.AdmissionTimeout)
	defer cancel()
	result := make(chan actionAdmission, 1)
	go func() { defer func() { <-p.admissions }(); result <- p.admit(admissionCtx, d, snapshot, auth) }()
	var admission actionAdmission
	select {
	case admission = <-result:
	case <-admissionCtx.Done():
		if ctx.Err() != nil {
			emit("deny", "admission_cancelled", "not_attempted")
			return nil, ctx.Err()
		}
		return deny("admission_timeout", 503)
	}
	if ctx.Err() != nil {
		emit("deny", "admission_cancelled", "not_attempted")
		return nil, ctx.Err()
	}
	if admissionCtx.Err() != nil {
		return deny("admission_timeout", 503)
	}
	if admission.reason != "" {
		return deny(admission.reason, admission.status)
	}
	if !admission.context.Caller.ExpiresAt.After(time.Now()) {
		return deny("authentication_expired", 401)
	}
	cancel() // Execute owns caller cancellation, not the admission deadline.
	var controls actionControls
	if p.runtime != nil {
		controls = p.runtime.controls[name]
	}
	for i, client := range controls.quotas {
		decision := &Decision{report: Report{Decision: "allow"}}
		client.checkQuota(ctx, admission.context.Caller, decision)
		for _, check := range decision.Checks() {
			check.ID = controls.quotaIDs[i]
			checks = append(checks, check)
		}
		if ctx.Err() != nil {
			emit("deny", "admission_cancelled", "not_attempted")
			return nil, ctx.Err()
		}
		if !decision.Allowed() {
			retry = decision.RetryAfterSeconds()
			return deny(decision.Reason(), decision.Status())
		}
	}
	work := func(workCtx context.Context) error {
		if e := workCtx.Err(); e != nil {
			return e
		}
		if !admission.context.Caller.ExpiresAt.After(time.Now()) {
			return &ActionDenied{Reason: "authentication_expired", Status: 401, ActionID: id}
		}
		attempted = true
		emit("allow", "authorized", "attempted")
		var workErr error
		value, workErr = d.Execute(workCtx, copyActionContext(admission.context))
		if workCtx.Err() != nil {
			return workCtx.Err()
		}
		return workErr
	}
	defer func() {
		if v := recover(); v != nil {
			emit("allow", "execution_failed", "unknown")
			panic(v)
		}
	}()
	if controls.concurrent != nil {
		decision, workErr := controls.concurrent.runConcurrent(ctx, admission.context.Caller, func(workCtx context.Context, check Check) error {
			checks = append(checks, check)
			return work(workCtx)
		})
		err = workErr
		if !attempted && !decision.Allowed && err == nil {
			checks = append(checks, decision.Check)
			retry = decision.RetryAfterSeconds
			return deny(decision.Check.Reason, decision.Status)
		}
		if errors.Is(err, errConcurrencyRelease) {
			checks = append(checks, Check{ID: "concurrency_release", Source: "shared", Mode: decision.Check.Mode, Decision: "unavailable", Reason: "concurrency_release_unavailable"})
			err = nil // Completed work is never retried because release/reporting failed.
		}
	} else {
		err = work(ctx)
	}
	if !attempted {
		var denied *ActionDenied
		if errors.As(err, &denied) {
			return deny(denied.Reason, denied.Status)
		}
		if ctx.Err() != nil {
			emit("deny", "admission_cancelled", "not_attempted")
			return nil, ctx.Err()
		}
		return deny("admission_unavailable", 503)
	}
	if err != nil {
		reason := "execution_failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			reason = "execution_cancelled"
		}
		emit("allow", reason, "unknown")
		return value, err
	}
	emit("allow", "authorized", "completed")
	return value, nil
}

// Flush waits for bounded hosted event delivery after draining action handlers.
func (p *ActionProtection[T]) Flush(ctx context.Context) error {
	if p.runtime == nil {
		return nil
	}
	return p.runtime.reporter.Flush(ctx)
}
