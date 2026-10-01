package main

import (
	"context"
	"encoding/json"
	"fmt"
	p "github.com/WebDecoy/ai-protection-go"
	"time"
)

func main() {
	reads, exports := 0, 0
	guard, err := p.NewActionProtection(p.ActionOptions[string]{PolicyVersion: "records_v1", Authenticate: func(_ context.Context, session string) (p.TrustedCaller, error) {
		if session != "fixture-session" {
			return p.TrustedCaller{}, fmt.Errorf("invalid session")
		}
		return p.TrustedCaller{Schema: 1, Subject: "reader", Tenant: "tenant-a", Issuer: "local-fixture", AuthenticationMethod: "session", ExpiresAt: time.Now().Add(time.Minute), Scopes: []string{"read"}}, nil
	}, Actions: map[string]p.ActionDefinition{
		"read": {RequiredScopes: []string{"read"}, Validate: func(_ context.Context, b json.RawMessage) (bool, error) {
			var a struct{ Record string }
			e := json.Unmarshal(b, &a)
			return a.Record != "", e
		}, Authorize: func(_ context.Context, c p.ActionContext) (bool, error) {
			var a struct{ Record string }
			_ = json.Unmarshal(c.Arguments, &a)
			return c.Caller.Tenant == "tenant-a" && a.Record == "a", nil
		}, Execute: func(_ context.Context, c p.ActionContext) (any, error) {
			var a struct{ Record string }
			_ = json.Unmarshal(c.Arguments, &a)
			if c.Caller.Tenant != "tenant-a" || a.Record != "a" {
				return nil, fmt.Errorf("ownership changed")
			}
			reads++
			return "authorized record", nil
		}},
		"export": {RequiredScopes: []string{"export"}, Validate: func(context.Context, json.RawMessage) (bool, error) { return true, nil }, Authorize: func(context.Context, p.ActionContext) (bool, error) { return false, nil }, Execute: func(context.Context, p.ActionContext) (any, error) { exports++; return nil, nil }},
	}})
	if err != nil {
		panic(err)
	}
	if _, err = guard.Run(context.Background(), "read", json.RawMessage(`{"Record":"a"}`), "fixture-session"); err != nil {
		panic(err)
	}
	for _, v := range []struct{ action, args, session string }{{"read", `{"Record":"b"}`, "fixture-session"}, {"export", `null`, "fixture-session"}, {"read", `{"Record":"a"}`, "forged-session"}} {
		if _, err = guard.Run(context.Background(), v.action, json.RawMessage(v.args), v.session); err == nil {
			panic("forbidden action admitted")
		}
	}
	if reads != 1 || exports != 0 {
		panic("execution counts")
	}
	fmt.Printf("allowed reads=%d forbidden exports=%d\n", reads, exports)
}
