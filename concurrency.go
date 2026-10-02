package aiprotection

import (
	"context"
	"errors"
	"strings"
	"time"
)

type Concurrency[T any] struct {
	RuleID, SubjectSecret                              string
	AccountLimit, FeatureLimit, TTLSeconds, MaxSeconds int
	Mode                                               Mode
	FailureMode                                        FailureMode
	Timeout                                            time.Duration
	Subject                                            func(T) QuotaSubject
}
type ConcurrencyDecision struct {
	Allowed                   bool
	Status, RetryAfterSeconds int
	Check                     Check
}

func prepareConcurrency[T any](q *Concurrency[T]) (*Concurrency[T], error) {
	if q == nil {
		return nil, nil
	}
	v := *q
	q = &v
	if q.Mode == "" {
		q.Mode = Observe
	}
	if q.FailureMode == "" {
		q.FailureMode = Open
	}
	if q.Timeout == 0 {
		q.Timeout = time.Second
	}
	if q.TTLSeconds == 0 {
		q.TTLSeconds = 30
	}
	if q.MaxSeconds == 0 {
		q.MaxSeconds = 300
	}
	_, e := prepareQuota(&AccountQuota[T]{RuleID: q.RuleID, SubjectSecret: q.SubjectSecret, Subject: q.Subject, Limit: 1, WindowSeconds: 1, Mode: q.Mode, FailureMode: q.FailureMode, Timeout: q.Timeout})
	if e != nil || q.AccountLimit < 1 || q.AccountLimit > 1000 || q.FeatureLimit < q.AccountLimit || q.FeatureLimit > 10000 || q.TTLSeconds < 6 || q.TTLSeconds > 120 || q.MaxSeconds < q.TTLSeconds || q.MaxSeconds > 900 || q.Timeout > time.Duration(q.TTLSeconds)*time.Second/6 {
		return nil, errors.New("invalid concurrency configuration")
	}
	return q, nil
}

var errConcurrencyRelease = errors.New("concurrency release unavailable; reservation retained")

type leaseResponse struct {
	Schema     int    `json:"schema"`
	Allowed    *bool  `json:"allowed"`
	Granted    bool   `json:"granted"`
	Reason     string `json:"reason"`
	LeaseID    string `json:"lease_id"`
	Retry      int    `json:"retry_after_seconds"`
	ValidForMS int64  `json:"valid_for_ms"`
}

// RunConcurrent owns a lease until work returns nil (confirmed completion).
// Work MUST honor ctx, await all provider work and not detach goroutines. Errors,
// panics and cancellation leave a conservative reservation until MaxSeconds.
// This does not call Check: use after normal admission, before inference.
func (c *Client[T]) RunConcurrent(ctx context.Context, trusted T, work func(context.Context) error) (decision ConcurrencyDecision, err error) {
	if work == nil {
		return decision, errors.New("work required")
	}
	return c.runConcurrent(ctx, trusted, func(ctx context.Context, _ Check) error { return work(ctx) })
}

// Internal callback exposes the admission check before execution for action evidence.
func (c *Client[T]) runConcurrent(ctx context.Context, trusted T, work func(context.Context, Check) error) (decision ConcurrencyDecision, err error) {
	q := c.config.Concurrency
	if q == nil || work == nil {
		return decision, errors.New("concurrency configuration and work required")
	}
	if e := ctx.Err(); e != nil {
		return decision, e
	}
	started := time.Now()
	decision = ConcurrencyDecision{Allowed: true, Check: Check{ID: "concurrency", Source: "shared", Mode: q.Mode, Decision: "unavailable", Reason: "concurrency_unavailable"}}
	subject, e := quotaSubject(&AccountQuota[T]{Subject: q.Subject}, trusted)
	nonce, _ := requestID()
	payload := map[string]any{"schema": 1, "operation": "acquire", "rule_id": q.RuleID, "mode": q.Mode, "nonce": nonce, "account_limit": q.AccountLimit, "feature_limit": q.FeatureLimit, "ttl_seconds": q.TTLSeconds, "max_seconds": q.MaxSeconds}
	if e == nil {
		payload["subject"] = quotaHash(q.SubjectSecret, "webdecoy.account-quota.v1", strings.ToLower(c.config.PropertyID), q.RuleID, "account", subject.AccountID)
	}
	rpc := func(parent context.Context, body map[string]any) (leaseResponse, error) {
		call, cancel := context.WithTimeout(parent, q.Timeout)
		defer cancel()
		var r leaseResponse
		e := c.json(call, "POST", "/api/v1/sdk/ai-abuse/concurrency", body, &r)
		if e == nil && (r.Schema != 1 || r.Allowed == nil || !code.MatchString(r.Reason) || r.Retry < 0 || r.Retry > q.MaxSeconds || (r.Granted && (!validUUID(r.LeaseID) || r.ValidForMS <= 0 || r.ValidForMS > int64(q.TTLSeconds)*1000))) {
			e = errors.New("invalid concurrency response")
		}
		return r, e
	}
	var grant leaseResponse
	if e == nil {
		grant, e = rpc(ctx, payload)
	}
	decision.Check.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	if e != nil {
		if ctx.Err() != nil {
			return decision, ctx.Err()
		}
		if q.Mode == Enforce && q.FailureMode == Closed {
			decision.Allowed = false
			decision.Status = 503
			return decision, nil
		}
		return decision, work(ctx, decision.Check)
	}
	decision.Check.Decision = "allow"
	decision.Check.Reason = grant.Reason
	if !*grant.Allowed {
		decision.Check.Decision = "deny"
	}
	if !grant.Granted {
		// Replayed nonce can never become a second execution permit, even in observe.
		decision.Allowed = false
		decision.Status = 429
		decision.RetryAfterSeconds = max(1, grant.Retry)
		return decision, nil
	}
	if q.Mode == Enforce && !*grant.Allowed {
		return decision, errors.New("invalid enforced lease grant")
	}
	if grant.Reason != "concurrency_allowed" && grant.Reason != "concurrency_exceeded" {
		return decision, errors.New("invalid lease reason")
	}
	// Conservative monotonic time: network time is charged against the grant.
	deadline := started.Add(time.Duration(grant.ValidForMS) * time.Millisecond)
	if time.Until(deadline) <= q.Timeout {
		return decision, errors.New("lease expired before work")
	}
	workCtx, cancel := context.WithDeadline(ctx, started.Add(time.Duration(q.MaxSeconds)*time.Second))
	defer cancel()
	body := map[string]any{}
	for k, v := range payload {
		body[k] = v
	}
	delete(body, "nonce")
	body["lease_id"] = grant.LeaseID
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		for {
			delay := min(time.Duration(q.TTLSeconds)*time.Second/3, time.Until(deadline)/3)
			if delay <= 0 {
				cancel()
				return
			}
			timer := time.NewTimer(delay)
			select {
			case <-done:
				timer.Stop()
				return
			case <-workCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			sent := time.Now()
			renew := map[string]any{}
			for k, v := range body {
				renew[k] = v
			}
			renew["operation"] = "renew"
			call, stop := context.WithDeadline(workCtx, deadline.Add(-100*time.Millisecond))
			r, e := rpc(call, renew)
			stop()
			if e != nil || !r.Granted || !*r.Allowed || r.LeaseID != grant.LeaseID || r.Reason != "concurrency_renewed" {
				cancel()
				return
			}
			deadline = sent.Add(time.Duration(r.ValidForMS) * time.Millisecond)
		}
	}()
	// A panic still stops heartbeat; capacity remains reserved, rather than claiming
	// detached upstream work has stopped. The original panic propagates unchanged.
	defer func() { close(done); cancel(); <-heartbeatDone }()
	if e := workCtx.Err(); e != nil {
		return decision, e
	}
	err = work(workCtx, decision.Check)
	closeWorkErr := workCtx.Err()
	if err == nil && closeWorkErr == nil {
		// Stop renewals before release; duplicate releases are idempotent at the server.
		cancel()
		<-heartbeatDone
		release := map[string]any{}
		for k, v := range body {
			release[k] = v
		}
		release["operation"] = "release"
		releaseCtx, stop := context.WithTimeout(context.Background(), q.Timeout)
		defer stop()
		if r, e := rpc(releaseCtx, release); e != nil || !*r.Allowed || r.Reason != "concurrency_released" {
			return decision, errConcurrencyRelease
		}
	} else if err == nil {
		err = closeWorkErr
	}
	return decision, err
}
