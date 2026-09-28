package aiprotection

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

type BudgetLimits struct {
	AccountTokens int64 `json:"account_tokens"`
	AccountMicros int64 `json:"account_micros"`
	TenantTokens  int64 `json:"tenant_tokens"`
	TenantMicros  int64 `json:"tenant_micros"`
	FeatureTokens int64 `json:"feature_tokens"`
	FeatureMicros int64 `json:"feature_micros"`
}
type BudgetSubject struct{ AccountID, OrganizationID string }
type BudgetPrice struct {
	Provider, Model                               string
	InputMicrosPerMillion, OutputMicrosPerMillion int64
}
type BudgetUsage struct {
	Provider, Model           string
	InputTokens, OutputTokens int64
}
type BudgetCall struct {
	PriceID                         string
	MaxInputTokens, MaxOutputTokens int64
}
type BudgetRuntime struct {
	Provider, Model                 string
	MaxInputTokens, MaxOutputTokens int64
}
type Budget[T any] struct {
	RuleID, SubjectSecret string
	WindowSeconds         int
	Limits                BudgetLimits
	Mode                  Mode
	FailureMode           FailureMode
	Timeout, MaxRuntime   time.Duration
	Prices                map[string]BudgetPrice
	Subject               func(T) BudgetSubject
}
type BudgetResult struct {
	Allowed, Started, Reserved, WouldDeny, Overrun bool
	Status, RetryAfterSeconds                      int
	Reason                                         string
}

func BudgetCost(p BudgetPrice, input, output int64) (int64, error) {
	if input < 0 || input > 10000000 || output < 0 || output > 10000000 || p.InputMicrosPerMillion < 0 || p.InputMicrosPerMillion > 1000000000 || p.OutputMicrosPerMillion < 0 || p.OutputMicrosPerMillion > 1000000000 {
		return 0, errors.New("invalid budget usage or price")
	}
	return (input*p.InputMicrosPerMillion + output*p.OutputMicrosPerMillion + 999999) / 1000000, nil
}

// OllamaBudgetUsage accepts only a final response with explicit token counts.
// Pointer counts distinguish missing usage from a confirmed zero-token call.
func OllamaBudgetUsage(model string, done bool, input, output *int64) *BudgetUsage {
	if !done || model == "" || input == nil || output == nil || *input < 0 || *output < 0 || *input > 10000000 || *output > 10000000 {
		return nil
	}
	return &BudgetUsage{Provider: "ollama", Model: model, InputTokens: *input, OutputTokens: *output}
}
func prepareBudget[T any](b *Budget[T]) (*Budget[T], error) {
	if b == nil {
		return nil, nil
	}
	v := *b
	b = &v
	if b.Mode == "" {
		b.Mode = Observe
	}
	if b.FailureMode == "" {
		b.FailureMode = Open
	}
	if b.Timeout == 0 {
		b.Timeout = time.Second
	}
	if b.MaxRuntime == 0 {
		b.MaxRuntime = 300 * time.Second
	}
	if !code.MatchString(b.RuleID) || !utf8.ValidString(b.SubjectSecret) || len(b.SubjectSecret) < 32 || b.Subject == nil || !validMode(b.Mode) || !validFailure(b.FailureMode) || b.WindowSeconds < 1 || b.WindowSeconds > 86400 || b.Timeout <= 0 || b.Timeout > 10*time.Second || b.MaxRuntime <= 0 || b.MaxRuntime > 900*time.Second || len(b.Prices) < 1 || len(b.Prices) > 64 {
		return nil, errors.New("invalid budget configuration")
	}
	enabled := false
	for _, n := range []int64{b.Limits.AccountTokens, b.Limits.AccountMicros, b.Limits.TenantTokens, b.Limits.TenantMicros, b.Limits.FeatureTokens, b.Limits.FeatureMicros} {
		if n < 0 || n > 1000000000000 {
			return nil, errors.New("invalid budget limits")
		}
		enabled = enabled || n > 0
	}
	if !enabled {
		return nil, errors.New("budget limit required")
	}
	prices := make(map[string]BudgetPrice, len(b.Prices))
	for id, p := range b.Prices {
		_, e := BudgetCost(p, 0, 0)
		if !code.MatchString(id) || !code.MatchString(p.Provider) || p.Model == "" || len(p.Model) > 128 || !utf8.ValidString(p.Model) || e != nil {
			return nil, errors.New("invalid budget price")
		}
		prices[id] = p
	}
	b.Prices = prices
	return b, nil
}

type budgetWireResponse struct {
	Schema        int    `json:"schema"`
	Allowed       *bool  `json:"allowed"`
	Granted       bool   `json:"granted"`
	Reason        string `json:"reason"`
	ReservationID string `json:"reservation_id"`
	Retry         int    `json:"retry_after_seconds"`
	Overrun       bool   `json:"overrun"`
}

// RunBudget wraps exactly one provider attempt after ordinary admission. Work must
// enforce supplied model/token bounds and await final usage; nil usage retains the
// maximum charge. Settlement failures are returned in Result, never as retry errors.
func (c *Client[T]) RunBudget(ctx context.Context, trusted T, call BudgetCall, work func(context.Context, BudgetRuntime) (*BudgetUsage, error)) (out BudgetResult, err error) {
	b := c.config.Budget
	if b == nil || work == nil {
		return out, errors.New("budget configuration and work required")
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	price, ok := b.Prices[call.PriceID]
	micros, e := BudgetCost(price, call.MaxInputTokens, call.MaxOutputTokens)
	if !ok || e != nil || call.MaxInputTokens+call.MaxOutputTokens < 1 {
		return out, errors.New("known price and conservative token bounds required")
	}
	runtime := BudgetRuntime{price.Provider, price.Model, call.MaxInputTokens, call.MaxOutputTokens}
	out.Allowed = true
	out.Reason = "budget_unavailable"
	// Trusted subject callbacks may fail; keep their raw data/errors out of telemetry.
	var subject BudgetSubject
	func() {
		defer func() {
			if recover() != nil {
				e = errors.New("invalid budget subject")
			}
		}()
		subject = b.Subject(trusted)
	}()
	for _, id := range []string{subject.AccountID, subject.OrganizationID} {
		if id == "" || len(id) > 256 || !utf8.ValidString(id) {
			e = errors.New("invalid budget subject")
		}
	}
	nonce, nonceErr := requestID()
	if nonceErr != nil {
		e = nonceErr
	}
	body := map[string]any{"schema": 1, "operation": "reserve", "rule_id": b.RuleID, "mode": b.Mode, "nonce": nonce, "window_seconds": b.WindowSeconds, "limits": b.Limits, "tokens": call.MaxInputTokens + call.MaxOutputTokens, "micros": micros}
	body["subject"] = quotaHash(b.SubjectSecret, "webdecoy.budget.v1", strings.ToLower(c.config.PropertyID), b.RuleID, "account", subject.AccountID)
	body["tenant"] = quotaHash(b.SubjectSecret, "webdecoy.budget.v1", strings.ToLower(c.config.PropertyID), b.RuleID, "tenant", subject.OrganizationID)
	rpc := func(parent context.Context, payload map[string]any) (budgetWireResponse, error) {
		call, stop := context.WithTimeout(parent, b.Timeout)
		defer stop()
		var r budgetWireResponse
		e := c.json(call, "POST", "/api/v1/sdk/ai-abuse/budget", payload, &r)
		if e == nil && (r.Schema != 1 || r.Allowed == nil || !code.MatchString(r.Reason) || r.Retry < 0 || r.Retry > 86400 || (r.Granted && !validUUID(r.ReservationID))) {
			e = errors.New("invalid budget response")
		}
		return r, e
	}
	var grant budgetWireResponse
	if e == nil {
		grant, e = rpc(ctx, body)
	}
	if e == nil {
		if grant.Granted && ((grant.Reason != "budget_allowed" && grant.Reason != "budget_exceeded") || (b.Mode == Enforce && !*grant.Allowed)) {
			e = errors.New("invalid budget grant")
		}
		if !grant.Granted && grant.Reason != "budget_exceeded" && grant.Reason != "budget_replay" {
			e = errors.New("invalid budget denial")
		}
	}
	if e != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if b.Mode == Enforce && b.FailureMode == Closed {
			out.Allowed = false
			out.Status = 503
			return out, nil
		}
	} else {
		if !grant.Granted {
			out.Allowed = false
			out.Status = 429
			out.RetryAfterSeconds = max(1, grant.Retry)
			out.Reason = grant.Reason
			return out, nil
		}
		out.Reserved = true
		out.WouldDeny = !*grant.Allowed
		out.Reason = "budget_usage_unknown"
	}
	workCtx, stop := context.WithTimeout(ctx, b.MaxRuntime)
	defer stop()
	if e := workCtx.Err(); e != nil {
		return out, e
	}
	out.Started = true
	usage, err := work(workCtx, runtime)
	if err != nil {
		return out, err
	}
	if !out.Reserved {
		return out, nil
	}
	if workCtx.Err() != nil || usage == nil || usage.Provider != price.Provider || usage.Model != price.Model {
		return out, nil
	}
	cost, e := BudgetCost(price, usage.InputTokens, usage.OutputTokens)
	if e != nil {
		return out, nil
	}
	out.Overrun = usage.InputTokens > call.MaxInputTokens || usage.OutputTokens > call.MaxOutputTokens
	body["operation"] = "settle"
	delete(body, "nonce")
	body["reservation_id"] = grant.ReservationID
	body["tokens"] = usage.InputTokens + usage.OutputTokens
	body["micros"] = cost
	r, e := rpc(context.Background(), body)
	out.Reason = "budget_settlement_unavailable"
	if e == nil && *r.Allowed && r.Reason == "budget_settled" {
		out.Reason = "budget_settled"
		out.Overrun = out.Overrun || r.Overrun
	}
	return out, nil
}
