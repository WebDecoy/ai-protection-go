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

func lifecycleEvent(t *testing.T, events <-chan ActionEvent) ActionEvent {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(time.Second):
		t.Fatal("missing lifecycle event")
		return ActionEvent{}
	}
}

func TestActionPolicyReplacementInFlight(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	old, _, oldEvents := actionFixture(t, func(o *ActionOptions[string]) {
		d := o.Actions["read"]
		d.Execute = func(context.Context, ActionContext) (any, error) {
			calls.Add(1)
			close(started)
			<-finish
			return "original", nil
		}
		o.Actions["read"] = d
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		v, e := old.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
		if e != nil || v != "original" {
			t.Error(v, e)
		}
	}()
	<-started
	replacement, deniedCalls, newEvents := actionFixture(t, func(o *ActionOptions[string]) {
		o.PolicyVersion = "v2"
		d := o.Actions["read"]
		d.Policy = func(context.Context, ActionContext) (bool, error) { return false, nil }
		o.Actions["read"] = d
	})
	_, err := replacement.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "")
	close(finish)
	<-done
	var denied *ActionDenied
	if !errors.As(err, &denied) || denied.Reason != "policy_denied" || deniedCalls.Load() != 0 || calls.Load() != 1 {
		t.Fatal(err, calls.Load(), deniedCalls.Load())
	}
	a, b := lifecycleEvent(t, oldEvents), lifecycleEvent(t, oldEvents)
	outcomes := map[string]bool{a.Outcome: true, b.Outcome: true}
	if a.PolicyVersion != "v1" || b.PolicyVersion != "v1" || a.ActionID != b.ActionID || !outcomes["attempted"] || !outcomes["completed"] {
		t.Fatal(a, b)
	}
	e := lifecycleEvent(t, newEvents)
	if e.PolicyVersion != "v2" || e.Outcome != "not_attempted" || e.Attempted {
		t.Fatal(e)
	}
}

func TestActionCallbackOwnedStreamLifecycle(t *testing.T) {
	for _, kind := range []string{"complete", "error", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, next := make(chan struct{}), make(chan struct{})
			original := errors.New("provider disconnected")
			var calls, cleaned atomic.Int32
			p, _, events := actionFixture(t, func(o *ActionOptions[string]) {
				d := o.Actions["read"]
				d.Execute = func(ctx context.Context, _ ActionContext) (any, error) {
					calls.Add(1)
					defer cleaned.Add(1)
					var output strings.Builder
					output.WriteString("first")
					close(started)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-next:
					}
					if kind == "error" {
						return nil, original
					}
					output.WriteString("second")
					return output.String(), nil
				}
				o.Actions["read"] = d
			})
			type result struct {
				value any
				err   error
			}
			done := make(chan result, 1)
			go func() { v, e := p.Run(ctx, "read", json.RawMessage(`{"record":"a"}`), ""); done <- result{v, e} }()
			<-started
			first := lifecycleEvent(t, events)
			if first.Outcome != "attempted" {
				t.Fatal(first)
			}
			if kind == "cancel" {
				cancel()
			} else {
				close(next)
			}
			r := <-done
			if kind == "complete" && (r.err != nil || r.value != "firstsecond") {
				t.Fatal(r)
			}
			if kind == "error" && r.err != original {
				t.Fatal(r)
			}
			if kind == "cancel" && !errors.Is(r.err, context.Canceled) {
				t.Fatal(r)
			}
			last := lifecycleEvent(t, events)
			want := "unknown"
			if kind == "complete" {
				want = "completed"
			}
			if last.Outcome != want || last.PolicyVersion != "v1" || last.ActionID != first.ActionID || !last.Attempted || calls.Load() != 1 || cleaned.Load() != 1 {
				t.Fatal(last, calls.Load(), cleaned.Load())
			}
		})
	}
}
