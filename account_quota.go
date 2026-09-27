package aiprotection

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// QuotaSubject must come from authenticated server state, after authorization.
// SessionID is optional; a session limit always supplements the account limit.
type QuotaSubject struct{ AccountID, SessionID string }
type AccountQuota[T any] struct {
	RuleID                             string // Stable feature/policy identifier, never supplied by the browser.
	SubjectSecret                      string // >=32 UTF-8 bytes; same secret on every JS/Go app replica.
	Limit, WindowSeconds, SessionLimit int
	Mode                               Mode        // Defaults to Observe. Independent of detector/dashboard mode.
	FailureMode                        FailureMode // Defaults to Open; choose Closed explicitly for a hard quota.
	Timeout                            time.Duration
	Subject                            func(T) QuotaSubject
}

func prepareQuota[T any](q *AccountQuota[T]) (*AccountQuota[T], error) {
	if q == nil {
		return nil, nil
	}
	copy := *q
	q = &copy
	if q.Mode == "" {
		q.Mode = Observe
	}
	if q.FailureMode == "" {
		q.FailureMode = Open
	}
	if q.Timeout == 0 {
		q.Timeout = time.Second
	}
	if !code.MatchString(q.RuleID) || len(q.SubjectSecret) < 32 || !utf8.ValidString(q.SubjectSecret) || q.Subject == nil || q.Limit < 1 || q.Limit > 1000000 || q.WindowSeconds < 1 || q.WindowSeconds > 86400 || q.SessionLimit < 0 || q.SessionLimit > q.Limit || !validMode(q.Mode) || !validFailure(q.FailureMode) || q.Timeout <= 0 || q.Timeout > 10*time.Second {
		return nil, errors.New("invalid account quota configuration")
	}
	return q, nil
}

// Each UTF-8 field is framed with its uint32 big-endian byte length. This avoids
// delimiter ambiguity and matches Node exactly (including Unicode identifiers).
func quotaHash(secret string, parts ...string) string {
	h := hmac.New(sha256.New, []byte(secret))
	var size [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(size[:], uint32(len(p)))
		h.Write(size[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func quotaSubject[T any](q *AccountQuota[T], trusted T) (s QuotaSubject, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("invalid quota subject")
		}
	}()
	s = q.Subject(trusted)
	if len(s.AccountID) == 0 || len(s.AccountID) > 256 || !utf8.ValidString(s.AccountID) || len(s.SessionID) > 256 || !utf8.ValidString(s.SessionID) || (q.SessionLimit > 0 && s.SessionID == "") {
		err = errors.New("invalid quota subject")
	}
	return
}
func (c *Client[T]) checkQuota(ctx context.Context, trusted T, d *Decision) {
	q := c.config.AccountQuota
	if q == nil || !d.Allowed() {
		return
	}
	start := time.Now()
	check := Check{ID: "account_quota", Source: "shared", Mode: q.Mode, Decision: "unavailable", Reason: "account_quota_unavailable"}
	var result struct {
		Schema    int    `json:"schema"`
		Allowed   *bool  `json:"allowed"`
		Reason    string `json:"reason"`
		Remaining *int   `json:"remaining"`
		Retry     *int   `json:"retry_after_seconds"`
		Reset     int64  `json:"reset_at"`
	}
	s, err := quotaSubject(q, trusted)
	if err == nil {
		args := []string{"webdecoy.account-quota.v1", strings.ToLower(c.config.PropertyID), q.RuleID, "account", s.AccountID}
		payload := map[string]any{"schema": 1, "rule_id": q.RuleID, "subject": quotaHash(q.SubjectSecret, args...), "limit": q.Limit, "window_seconds": q.WindowSeconds, "session_limit": q.SessionLimit}
		if q.SessionLimit > 0 {
			payload["session"] = quotaHash(q.SubjectSecret, "webdecoy.account-quota.v1", strings.ToLower(c.config.PropertyID), q.RuleID, "session", s.AccountID, s.SessionID)
		}
		call, cancel := context.WithTimeout(ctx, q.Timeout)
		defer cancel()
		err = c.json(call, "POST", "/api/v1/sdk/ai-abuse/quota", payload, &result)
		if err == nil && (result.Schema != 1 || result.Allowed == nil || result.Remaining == nil || result.Retry == nil || *result.Remaining < 0 || *result.Remaining > q.Limit || result.Reset <= 0 || (*result.Allowed && (result.Reason != "account_quota_allowed" || *result.Retry != 0)) || (!*result.Allowed && (result.Reason != "account_quota_exceeded" || *result.Retry < 1 || *result.Retry > q.WindowSeconds))) {
			err = errors.New("invalid account quota response")
		}
	}
	if err != nil {
		d.report.Degraded = true
		if q.Mode == Enforce && q.FailureMode == Closed {
			d.report.Decision = "deny"
			d.report.Reason = "account_quota_unavailable"
			d.report.Action = "denied_unavailable"
			d.status = 503
		}
	} else {
		check.Decision = "allow"
		check.Reason = result.Reason
		if !*result.Allowed {
			check.Decision = "deny"
			if q.Mode == Enforce {
				d.report.Decision = "deny"
				d.report.Reason = result.Reason
				d.report.Action = "denied"
				d.status = 429
				d.retryAfter = *result.Retry
			}
		}
	}
	check.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
	d.report.Checks = append(d.report.Checks, check)
}
