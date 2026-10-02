package aiprotection

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// ActionRuntime connects shared controls and bounded hosted evidence. Keep the
// same SubjectSecret on every application replica and language runtime.
type ActionRuntime struct {
	BaseURL, APIKey, PropertyID, SubjectSecret string
	HTTPClient                                 *http.Client
	ReportingTimeout                           time.Duration
	MaxPendingReports                          int
}
type ActionQuota struct {
	RuleID               string
	Limit, WindowSeconds int
	Mode                 Mode
	FailureMode          FailureMode
	Timeout              time.Duration
}
type ActionConcurrency struct {
	RuleID                                             string
	AccountLimit, FeatureLimit, TTLSeconds, MaxSeconds int
	Mode                                               Mode
	FailureMode                                        FailureMode
	Timeout                                            time.Duration
}
type ActionLimits struct {
	CallerQuota, TenantQuota *ActionQuota
	Concurrency              *ActionConcurrency
}
type actionControls struct {
	quotas     []*Client[TrustedCaller]
	quotaIDs   []string
	concurrent *Client[TrustedCaller]
}
type preparedActionRuntime struct {
	reporter *Client[TrustedCaller]
	controls map[string]actionControls
}

func prepareActionRuntime(o *ActionRuntime, definitions map[string]ActionDefinition) (*preparedActionRuntime, error) {
	if o == nil {
		for _, d := range definitions {
			if d.Limits != nil {
				return nil, errors.New("shared runtime required for action limits")
			}
		}
		return nil, nil
	}
	v := *o
	o = &v
	if len(o.SubjectSecret) < 32 || !utf8.ValidString(o.SubjectSecret) || strings.ContainsFunc(o.APIKey, func(r rune) bool { return r < 33 || r > 126 }) {
		return nil, errors.New("invalid shared action runtime")
	}
	config := Config[TrustedCaller]{BaseURL: o.BaseURL, APIKey: o.APIKey, PropertyID: o.PropertyID, HTTPClient: o.HTTPClient, ReportingTimeout: o.ReportingTimeout, MaxPendingReports: o.MaxPendingReports}
	reporter, err := New(config)
	if err != nil {
		return nil, err
	}
	runtime := &preparedActionRuntime{reporter: reporter, controls: map[string]actionControls{}}
	ids := map[string]bool{}
	claim := func(id string) bool {
		if ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	subject := func(c TrustedCaller) QuotaSubject {
		return QuotaSubject{AccountID: quotaHash(o.SubjectSecret, "webdecoy.actions.caller.v1", c.Issuer, c.Tenant, c.Subject)}
	}
	tenant := func(c TrustedCaller) QuotaSubject {
		return QuotaSubject{AccountID: quotaHash(o.SubjectSecret, "webdecoy.actions.tenant.v1", c.Tenant)}
	}
	for name, d := range definitions {
		if d.Limits == nil {
			continue
		}
		controls := actionControls{}
		for i, q := range []*ActionQuota{d.Limits.CallerQuota, d.Limits.TenantQuota} {
			if q == nil {
				continue
			}
			if !claim(q.RuleID) {
				return nil, errors.New("action limit rule IDs must be distinct")
			}
			cfg := config
			getSubject := subject
			id := "caller_quota"
			if i == 1 {
				getSubject = tenant
				id = "tenant_quota"
			}
			cfg.AccountQuota = &AccountQuota[TrustedCaller]{RuleID: q.RuleID, SubjectSecret: o.SubjectSecret, Limit: q.Limit, WindowSeconds: q.WindowSeconds, Mode: q.Mode, FailureMode: q.FailureMode, Timeout: q.Timeout, Subject: getSubject}
			c, e := New(cfg)
			if e != nil {
				return nil, e
			}
			controls.quotas = append(controls.quotas, c)
			controls.quotaIDs = append(controls.quotaIDs, id)
		}
		if q := d.Limits.Concurrency; q != nil {
			if !claim(q.RuleID) {
				return nil, errors.New("action limit rule IDs must be distinct")
			}
			cfg := config
			cfg.Concurrency = &Concurrency[TrustedCaller]{RuleID: q.RuleID, SubjectSecret: o.SubjectSecret, AccountLimit: q.AccountLimit, FeatureLimit: q.FeatureLimit, TTLSeconds: q.TTLSeconds, MaxSeconds: q.MaxSeconds, Mode: q.Mode, FailureMode: q.FailureMode, Timeout: q.Timeout, Subject: subject}
			c, e := New(cfg)
			if e != nil {
				return nil, e
			}
			controls.concurrent = c
		}
		runtime.controls[name] = controls
	}
	return runtime, nil
}
func (r *preparedActionRuntime) report(e ActionEvent) {
	report := Report{Schema: 2, RequestID: e.EventID, Timestamp: e.Timestamp, Decision: e.Decision, Reason: e.Reason, Action: "forwarded", ToolAction: &ToolActionReport{ActionID: e.ActionID, Name: e.Action, PolicyVersion: e.PolicyVersion, Outcome: e.Outcome}, Checks: []Check{{ID: "action_boundary", Source: "local", Mode: Enforce, Decision: e.Decision, Reason: e.Reason}}}
	if !e.Attempted {
		report.Action = "denied"
	}
	for _, check := range e.Checks {
		check.OperationID = ""
		report.Checks = append(report.Checks, check)
		if check.Decision == "unavailable" {
			report.Degraded = true
		}
	}
	r.reporter.Report(&Decision{owner: r.reporter, report: report}, Outcome{HandlerAttempted: e.Attempted, HandlerError: e.Outcome == "unknown"})
}
