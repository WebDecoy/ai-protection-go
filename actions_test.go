package aiprotection

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func actionCaller() TrustedCaller {
	return TrustedCaller{Schema: 1, Subject: "reader", Tenant: "tenant-a", Issuer: "fixture", AuthenticationMethod: "session", ExpiresAt: time.Now().Add(time.Minute), Scopes: []string{"read"}}
}
func actionFixture(t *testing.T, change func(*ActionOptions[string])) (*ActionProtection[string], *atomic.Int32, chan ActionEvent) {
	t.Helper()
	calls := &atomic.Int32{}
	events := make(chan ActionEvent, 20)
	o := ActionOptions[string]{PolicyVersion: "v1", Authenticate: func(context.Context, string) (TrustedCaller, error) { return actionCaller(), nil }, OnEvent: func(e ActionEvent) { events <- e }, Actions: map[string]ActionDefinition{"read": {
		RequiredScopes: []string{"read"}, Validate: func(_ context.Context, b json.RawMessage) (bool, error) {
			var a map[string]string
			e := json.Unmarshal(b, &a)
			return a["record"] != "", e
		},
		Authorize: func(_ context.Context, c ActionContext) (bool, error) {
			var a map[string]string
			_ = json.Unmarshal(c.Arguments, &a)
			return c.Caller.Tenant == "tenant-a" && a["record"] == "a", nil
		},
		Execute: func(context.Context, ActionContext) (any, error) { calls.Add(1); return "result", nil }}}}
	if change != nil {
		change(&o)
	}
	p, e := NewActionProtection(o)
	if e != nil {
		t.Fatal(e)
	}
	return p, calls, events
}
func TestActionAllowed(t *testing.T) {
	p, c, events := actionFixture(t, nil)
	v, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "session")
	if e != nil || v != "result" || c.Load() != 1 {
		t.Fatal(v, e, c.Load())
	}
	for range 2 {
		select {
		case ev := <-events:
			b, _ := json.Marshal(ev)
			for _, secret := range []string{"reader", "tenant-a", "record", "fixture"} {
				if strings.Contains(string(b), secret) {
					t.Fatal(string(b))
				}
			}
		case <-time.After(time.Second):
			t.Fatal("missing event")
		}
	}
}
func TestActionDenials(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*ActionOptions[string])
		args         string
	}{
		{name: "tenant", reason: "permission_denied", args: `{"record":"b"}`},
		{name: "scopes", reason: "missing_scope", change: func(o *ActionOptions[string]) {
			o.Authenticate = func(context.Context, string) (TrustedCaller, error) {
				c := actionCaller()
				c.Scopes = nil
				return c, nil
			}
		}},
		{name: "identity", reason: "authentication_required", change: func(o *ActionOptions[string]) {
			o.Authenticate = func(context.Context, string) (TrustedCaller, error) { return TrustedCaller{}, nil }
		}},
		{name: "expiry", reason: "authentication_required", change: func(o *ActionOptions[string]) {
			o.Authenticate = func(context.Context, string) (TrustedCaller, error) {
				c := actionCaller()
				c.ExpiresAt = time.Now().Add(-time.Second)
				return c, nil
			}
		}},
		{name: "malformed", reason: "invalid_arguments", args: `{"record":`},
		{name: "duplicate keys", reason: "invalid_arguments", args: `{"record":"a","record":"b"}`},
		{name: "big", reason: "invalid_arguments", args: `"` + strings.Repeat("a", 17000) + `"`},
		{name: "authorization outage", reason: "authorization_unavailable", change: func(o *ActionOptions[string]) {
			d := o.Actions["read"]
			d.Authorize = func(context.Context, ActionContext) (bool, error) { return false, errors.New("private") }
			o.Actions["read"] = d
		}},
		{name: "policy", reason: "policy_denied", change: func(o *ActionOptions[string]) {
			d := o.Actions["read"]
			d.Policy = func(context.Context, ActionContext) (bool, error) { return false, nil }
			o.Actions["read"] = d
		}},
		{name: "panic", reason: "authorization_unavailable", change: func(o *ActionOptions[string]) {
			d := o.Actions["read"]
			d.Authorize = func(context.Context, ActionContext) (bool, error) { panic("private") }
			o.Actions["read"] = d
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, c, _ := actionFixture(t, tt.change)
			args := tt.args
			if args == "" {
				args = `{"record":"a"}`
			}
			_, e := p.Run(context.Background(), "read", json.RawMessage(args), "session")
			var denied *ActionDenied
			if !errors.As(e, &denied) || denied.Reason != tt.reason || c.Load() != 0 {
				t.Fatal(e, c.Load())
			}
		})
	}
}
func TestActionUnknown(t *testing.T) {
	p, c, _ := actionFixture(t, nil)
	_, e := p.Run(context.Background(), "export", json.RawMessage(`null`), "session")
	var d *ActionDenied
	if !errors.As(e, &d) || d.Reason != "action_not_registered" || c.Load() != 0 {
		t.Fatal(e)
	}
}
func TestActionApplicationDenialWins(t *testing.T) {
	var policy atomic.Int32
	p, c, _ := actionFixture(t, func(o *ActionOptions[string]) {
		d := o.Actions["read"]
		d.Policy = func(context.Context, ActionContext) (bool, error) { policy.Add(1); return true, nil }
		o.Actions["read"] = d
	})
	_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"b"}`), "")
	if e == nil || policy.Load() != 0 || c.Load() != 0 {
		t.Fatal(e)
	}
}
func TestActionSnapshots(t *testing.T) {
	p, _, _ := actionFixture(t, func(o *ActionOptions[string]) {
		d := o.Actions["read"]
		d.Authorize = func(_ context.Context, c ActionContext) (bool, error) {
			c.Caller.Scopes[0] = "export"
			c.Arguments[0] = '!'
			return true, nil
		}
		d.Execute = func(_ context.Context, c ActionContext) (any, error) {
			if c.Caller.Scopes[0] != "read" || c.Arguments[0] != '{' {
				t.Error("mutated execution context")
			}
			return nil, nil
		}
		o.Actions["read"] = d
	})
	_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	if e != nil {
		t.Fatal(e)
	}
}
func TestActionLateAuthenticationNeverDispatches(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	p, c, _ := actionFixture(t, func(o *ActionOptions[string]) {
		o.AdmissionTimeout = 10 * time.Millisecond
		o.Authenticate = func(context.Context, string) (TrustedCaller, error) {
			<-release
			defer close(finished)
			return actionCaller(), nil
		}
	})
	_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	var d *ActionDenied
	if !errors.As(e, &d) || d.Reason != "admission_timeout" {
		t.Fatal(e)
	}
	close(release)
	<-finished
	if c.Load() != 0 {
		t.Fatal("late dispatch")
	}
}
func TestActionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, c, _ := actionFixture(t, func(o *ActionOptions[string]) {
		d := o.Actions["read"]
		d.Authorize = func(context.Context, ActionContext) (bool, error) { cancel(); return true, nil }
		o.Actions["read"] = d
	})
	_, e := p.Run(ctx, "read", json.RawMessage(`{"record":"a"}`), "")
	if !errors.Is(e, context.Canceled) || c.Load() != 0 {
		t.Fatal(e)
	}
}
func TestActionExecutionUsesCallerDeadline(t *testing.T) {
	p, _, _ := actionFixture(t, func(o *ActionOptions[string]) {
		o.AdmissionTimeout = 10 * time.Millisecond
		d := o.Actions["read"]
		d.Execute = func(ctx context.Context, _ ActionContext) (any, error) {
			time.Sleep(20 * time.Millisecond)
			return "ok", ctx.Err()
		}
		o.Actions["read"] = d
	})
	v, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	if e != nil || v != "ok" {
		t.Fatal(v, e)
	}
}
func TestActionExecutionErrorPreserved(t *testing.T) {
	original := errors.New("provider failed")
	var calls atomic.Int32
	p, _, _ := actionFixture(t, func(o *ActionOptions[string]) {
		d := o.Actions["read"]
		d.Execute = func(context.Context, ActionContext) (any, error) { calls.Add(1); return nil, original }
		o.Actions["read"] = d
	})
	_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	if e != original || calls.Load() != 1 {
		t.Fatal(e)
	}
}
func TestActionStalledVerifiersBounded(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p, c, _ := actionFixture(t, func(o *ActionOptions[string]) {
		o.OnEvent = nil
		o.AdmissionTimeout = time.Millisecond
		o.Authenticate = func(context.Context, string) (TrustedCaller, error) { <-release; return actionCaller(), nil }
	})
	for range 32 {
		_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
		if e == nil {
			t.Fatal("unexpected admission")
		}
	}
	_, e := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	var d *ActionDenied
	if !errors.As(e, &d) || d.Reason != "admission_unavailable" || c.Load() != 0 {
		t.Fatal(e)
	}
}
func TestActionJSONBounds(t *testing.T) {
	for _, raw := range []string{`1e9999`, strings.Repeat(`[`, 14) + `null` + strings.Repeat(`]`, 14), `{"__proto__":{}}`, `true false`} {
		if actionJSON([]byte(raw)) {
			t.Fatal(raw)
		}
	}
}
