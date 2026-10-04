package aiprotection

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestSharedCallerContract(t *testing.T) {
	data, err := os.ReadFile("testdata/caller-contract-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name   string
		Caller struct {
			Schema                                                  int
			Subject, Tenant, Issuer, AuthenticationMethod, ClientID string
			Scopes                                                  []string
			ExpiresAt                                               int64
		}
		Arguments json.RawMessage
		Reason    string
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			c := v.Caller
			p, calls, _ := actionFixture(t, func(o *ActionOptions[string]) {
				o.Authenticate = func(context.Context, string) (TrustedCaller, error) {
					return TrustedCaller{Schema: c.Schema, Subject: c.Subject, Tenant: c.Tenant, Issuer: c.Issuer, AuthenticationMethod: c.AuthenticationMethod, ClientID: c.ClientID, Scopes: c.Scopes, ExpiresAt: time.UnixMilli(c.ExpiresAt)}, nil
				}
			})
			result, err := p.Run(context.Background(), "read", v.Arguments, "session")
			if v.Reason == "allow" {
				if err != nil || result != "result" || calls.Load() != 1 {
					t.Fatal(result, err, calls.Load())
				}
			} else {
				var denied *ActionDenied
				if !errors.As(err, &denied) || denied.Reason != v.Reason || calls.Load() != 0 {
					t.Fatal(err, calls.Load())
				}
			}
		})
	}
}

func TestCallerInvalidUTF8NeverDispatches(t *testing.T) {
	for _, field := range []string{"subject", "tenant", "issuer", "method", "client", "scope"} {
		t.Run(field, func(t *testing.T) {
			p, calls, _ := actionFixture(t, func(o *ActionOptions[string]) {
				o.Authenticate = func(context.Context, string) (TrustedCaller, error) {
					c := actionCaller()
					bad := string([]byte{0xff})
					switch field {
					case "subject":
						c.Subject = bad
					case "tenant":
						c.Tenant = bad
					case "issuer":
						c.Issuer = bad
					case "method":
						c.AuthenticationMethod = bad
					case "client":
						c.ClientID = bad
					case "scope":
						c.Scopes = []string{"read", bad}
					}
					return c, nil
				}
			})
			_, err := p.Run(context.Background(), "read", json.RawMessage(`{"record":"a"}`), "session")
			var denied *ActionDenied
			if !errors.As(err, &denied) || denied.Reason != "authentication_required" || calls.Load() != 0 {
				t.Fatal(err, calls.Load())
			}
		})
	}
}
