package aiprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	RequiredScopes []string
	Validate       func(context.Context, json.RawMessage) (bool, error)
	Authorize      func(context.Context, ActionContext) (bool, error)
	Policy         func(context.Context, ActionContext) (bool, error)
	// Execute must await all work; this preview does not own live stream completion.
	Execute func(context.Context, ActionContext) (any, error)
}
type ActionEvent struct {
	Schema        int    `json:"schema"`
	ActionID      string `json:"actionId"`
	Action        string `json:"action"`
	PolicyVersion string `json:"policyVersion"`
	Evaluation    string `json:"evaluation"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	Attempted     bool   `json:"attempted"`
	Outcome       string `json:"outcome"`
}
type ActionDenied struct {
	Reason   string
	Status   int
	ActionID string
}

func (e *ActionDenied) Error() string { return e.Reason }

type ActionOptions[T any] struct {
	PolicyVersion    string
	Authenticate     func(context.Context, T) (TrustedCaller, error)
	Actions          map[string]ActionDefinition
	AdmissionTimeout time.Duration
	OnEvent          func(ActionEvent)
}
type ActionProtection[T any] struct {
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
	return &ActionProtection[T]{options: o, admissions: make(chan struct{}, 32), observers: make(chan struct{}, 100)}, nil
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
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(b)
	d, known := p.options.Actions[name]
	eventName := name
	if !known {
		eventName = "unregistered"
	}
	attempted := false
	emit := func(decision, reason, outcome string) {
		p.emit(ActionEvent{1, id, eventName, p.options.PolicyVersion, "local", decision, reason, attempted, outcome})
	}
	deny := func(reason string, status int) (any, error) {
		emit("deny", reason, "not_attempted")
		return nil, &ActionDenied{reason, status, id}
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
	attempted = true
	emit("allow", "authorized", "attempted")
	defer func() {
		if v := recover(); v != nil {
			emit("allow", "execution_failed", "unknown")
			panic(v)
		}
	}()
	value, err = d.Execute(ctx, copyActionContext(admission.context))
	if ctx.Err() != nil {
		emit("allow", "execution_cancelled", "unknown")
		return nil, ctx.Err()
	}
	if err != nil {
		emit("allow", "execution_failed", "unknown")
		return value, err
	}
	emit("allow", "authorized", "completed")
	return value, nil
}
