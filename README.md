# WebDecoy AI Protection for Go

Local application policies plus WebDecoy cloud detection for Go AI endpoints.
Zero third-party dependencies. Requires Go 1.26.1 or newer.

**Alpha release: `v0.1.0-alpha.2`.** Licensed under [Apache-2.0](LICENSE).
The hosted WebDecoy detector is a separate service and is not included here.

## Install

```sh
go get github.com/WebDecoy/ai-protection-go@v0.1.0-alpha.2
```

Use `https://ai-protection.webdecoy.com` as `BaseURL`, your WebDecoy property ID,
and a server-only API key scoped to that property with Write Detections permission.
Start in observation mode and review results at
[AI Protection](https://app.webdecoy.com/ai-protection).

## Integrate before inference

Create a shared client once at startup. The application's Go type supplies trusted
context to local rules; context is never serialized to WebDecoy.

```go
import protection "github.com/WebDecoy/ai-protection-go"

type UserContext struct { CanGenerate bool }

client, err := protection.New(protection.Config[UserContext]{
    BaseURL: "https://ai-protection.webdecoy.com",
    APIKey: serverAPIKey,
    PropertyID: propertyID,
    Mode: protection.Observe,
    Rules: []protection.Rule[UserContext]{{
        ID: "generation_entitlement",
        Mode: protection.Enforce,
        Evaluate: func(u UserContext) (protection.RuleResult, error) {
            return protection.RuleResult{
                Allowed: u.CanGenerate,
                Reason: "generation_entitlement_required",
            }, nil
        },
    }},
})
// Handle err at startup. Reuse client across requests.
```

Inside the route, after authentication, ownership checks and input validation:

```go
metadata := protection.Request{
    IP: trustedClientIP, // netip.Addr from verified ingress; never blindly trust X-Forwarded-For
    Method: r.Method,
    Route: "/protests/{id}/interview/respond", // normalized; never a real property ID
    Headers: r.Header,
}
decision, err := client.Check(r.Context(), metadata, UserContext{CanGenerate: authorized})
// Handle err, including caller cancellation. A detector outage returns a decision,
// not a transport error, unless the caller itself has cancelled.
// If !decision.Allowed(), return decision.Status()/Reason() BEFORE SSE headers.
// Recheck r.Context().Err() immediately before model invocation.
// Call client.Report(decision, protection.Outcome{...}) once on completion.
```

Or use `client.Protect(w, r, metadata, trustedContext, nextHandler)`. The wrapper
checks cancellation before invoking `nextHandler`, returns JSON on denial, and
queues reporting automatically. It passes the original writer and request through
unchanged (including Flusher/Hijacker/ResponseController support). It does not read
or rewrite request bodies, SSE, model output or model-provider calls. Because it
does not wrap the writer, it does not infer response status: supply `Outcome.Status`
when using the explicit API if your application knows it. Handler invocation is
not proof of a model call, completed response or provider billing.

## Availability and policy

- Cloud mode defaults to enforce; start pilots explicitly in observe. Actual cloud
  enforcement also requires the property dashboard mode and account entitlement.
- Local rules default to observe. Explicit local enforcement is independent of
  cloud mode, subscription or cloud availability; customer application policies
  remain in force during outages. First enforced denial determines status/reason.
- Rule errors, panics or invalid results become `local_rule_error`. An enforced
  rule defaults to failure-closed (503); explicitly set its FailureMode to Open
  when appropriate. Rule callbacks must be cheap and synchronous.
- Remote detector failures default to fail-open. Unknown/mismatched account state
  or an unavailable trusted IP also allow with degraded coverage and no scoring.
- Local allow never bypasses cloud checks. Local denial skips blocking cloud calls;
  it can still be reported asynchronously.
- No allow-verdict caching. Account bindings cache for 60 seconds, failures for
  5 seconds; expired grants aren't reused. Concurrent lookups coalesce.
- Account lookup and detection each default to a one-second timeout. A cold check
  may therefore wait roughly two seconds. Caller cancellation takes precedence.
- No distributed quotas, prompt-injection detection or guaranteed spending cap.

`Decision` exposes `Allowed`, `Reason`, `Status`, `ID`, `Degraded`, and `Checks`.
Results are private snapshots, and `Checks()` returns a copy. Foreign or repeated
decisions cannot inject duplicate report events into another client.

## Privacy and reporting

Detection sends the normalized route, method, client IP, user agent, header names,
accept-language and accept-encoding. It excludes query strings, prompts, request
bodies, session cookie/authentication values and application context.
Opting into browser evidence forwards only the WebDecoy receipt cookie. Choose non-sensitive
rule IDs/reason codes: they are visible in reports and possibly denial responses.

Central reporting uses the same bounded schema as the JavaScript SDK: check
results, request ID/timestamp, decision, degraded coverage and explicit handler
outcome. No raw IP, application identity, prompt or context is included. Reports
bind to the API key's property with a matching property header. Ingest deduplicates
and the dashboard labels these as SDK-reported outcomes, separate from detector
evidence; seven-day pilot retention applies.

`Report` returns immediately and uses a bounded number of background deliveries
(default 100). HTTP delivery has an independent timeout (default one second) so
request cancellation does not erase its outcome. `OnReport(ctx, report)` provides
an independent custom sink. Each sink receives its own snapshot; panics/errors
are contained. Custom sinks and transports MUST honor context. A stuck custom
sink keeps its slot occupied instead of creating unbounded replacement goroutines.

`DisableCentralReporting` opts out of central reports. There are no automatic
retries or durable delivery guarantees. Full queues/drop/failure logs do not
change admission. Call `Flush(ctx)` after draining HTTP handlers during shutdown;
a host that freezes execution after returning a response needs a lifecycle
mechanism or explicit bounded flush. Reports are best effort, not a billing ledger.

## Examples and validation

`examples/http` is a loopback-only authenticated SSE example using a fake model.
Configure WEBDECOY_URL, WEBDECOY_KEY, WEBDECOY_PROPERTY_ID and EXAMPLE_TOKEN, then
run `go run ./examples/http`. The fixed demo plan is not a production user system.
No paid model provider is called.

```sh
go test -race ./...
go vet ./...
```

The JS SDK's experimental HMAC subject/shadow-rate comparison is intentionally
not ported: it is not needed for admission or the reporting contract. This module
also takes explicit request metadata instead of guessing proxy trust or route
normalization. Use the hosted AI Protection endpoint for account/config, detection and reporting.

## Shared account quotas (opt-in)

Set `Config[T].AccountQuota` after authentication and application authorization:

```go
AccountQuota: &protection.AccountQuota[AuthenticatedUser]{
    RuleID: "chat_v1", SubjectSecret: secretSharedAcrossReplicas,
    Limit: 20, WindowSeconds: 60,
    Mode: protection.Enforce, FailureMode: protection.Open,
    Subject: func(user AuthenticatedUser) protection.QuotaSubject {
        return protection.QuotaSubject{AccountID: user.DatabaseID}
    },
},
```

The callback receives only caller-provided trusted server context. Never source its
account/session identity or policy from browser claims. Optional `SessionLimit`
and `SessionID` add an account-bound session cap; rotating sessions does not reset
the account counter. IPs/shared NAT do not determine quota identity.

Uses the hosted `/api/v1/sdk/ai-abuse/quota` endpoint. The quota
mode defaults to `Observe`, failure policy to `Open`, and timeout to one second;
these are independent of cloud detection and dashboard mode. Explicit
`FailureMode: Closed` returns 503 for unavailable/invalid quota state. Enforced
exhaustion returns 429 and `Retry-After`; explicit `Check` callers can use
`RetryAfterSeconds()` and must enforce the decision themselves.

Observation consumes the same counter as enforcement. In default schema 1, each
allowed admission consumes a unit, including retried or later-cancelled requests;
there are no automatic retries or refunds. Opt-in schema 2 adds bounded recovery
of the same admission (see below). Fixed UTC epoch windows
permit up to twice the limit across a boundary. This is not concurrency admission
or model-dollar accounting, and a timeout may happen after a committed increment.

The SDK sends property/feature-scoped HMAC-SHA256 pseudonyms, not raw account IDs,
local rule context or prompts. Use a random secret of at least 32 UTF-8 bytes,
identical on every Go/JS replica. Rotation resets quotas; coordinate after the
longest window. Pseudonyms remain correlatable and are not anonymous. Expired
buckets are removed on access and by an hourly sweep; healthy retention is at
most the 24-hour maximum window plus a sweep, extended if cleanup fails/backlogs.

Policy settings are immutable for a rule ID: inconsistent replicas get an
unavailable check instead of resetting a bucket. Versioning a rule starts new
counters deliberately. Backend limits are 32 policies and 10,000 active
account/session buckets per property. Capacity/state errors follow the quota's
failure policy; detector fail-open remains independent.


## Distributed concurrency

Optional concurrency policy shares per-account and property/feature capacity
across app replicas. Defaults are observe/open; detector failure policy is
independent. Authenticate first and derive the account ID from trusted server
state. Keep rule IDs and subject secrets identical across replicas.

Configure `Config.Concurrency` with `RuleID`, `SubjectSecret`, `AccountLimit`,
`FeatureLimit`, and a `Subject` function returning `QuotaSubject{AccountID: ...}`.
`Protect` owns the lease for the handler lifetime, preserves the writer/body,
and adds cancellation to the request context. Await all provider work before
returning. For explicit error/completion ownership, use `RunConcurrent` after
normal admission; `Check` does not acquire a lease. Never automatically retry
provider work because RunConcurrent returned an error: work may have occurred.

Heartbeat TTL defaults to 30 seconds and maximum runtime to 300 seconds.
Confirmed completion releases immediately. Errors, cancellation, crashes and
lease loss retain capacity until maximum runtime, because cancellation is not
proof a remote provider stopped. Upstream work must honor cancellation and have
a real runtime bound. Fail-open outages cannot guarantee a concurrency cap.
Released replay tombstones remain 24 hours: the pilot cap is 10,000 granted
acquisitions/day/property and 32 policies/property. This is not a throughput SLA.


## Upstream model budgets

Opt-in token and integer micro-USD budgets reserve a conservative maximum before
each provider attempt and reconcile only confirmed usage. Configure account,
customer-organization and feature limits, a fixed UTC window, a trusted subject
callback, and an explicit versioned model price catalog. Rates use micro-USD per
million input/output tokens. Unknown prices are rejected before work; an explicit
zero rate is permitted for intentionally free model usage, not unmeasured hosting.

Set `Config.Budget` and call `RunBudget(ctx, user, BudgetCall{PriceID: ...,
MaxInputTokens: ..., MaxOutputTokens: ...}, work)` after ordinary admission.
Check the returned `BudgetResult` for denial/status and accounting outcomes.
The callback receives `BudgetRuntime` and must await all work before returning
`*BudgetUsage`; nil usage conservatively retains the maximum. Work errors/panics
propagate, but settlement failures are result reasons, not provider retry errors.
`Protect`/`Check` do not infer per-call usage or acquire budget reservations.

Defaults are observe/open, independently of detector availability. A hard budget
requires explicit enforce/closed plus correctly enforced input/output bounds,
accurate complete prices/usage and no hidden provider retries. Every retry,
fallback and tool-loop model call needs a fresh reservation. Cancellation/crash/
missing usage never automatically refunds charges. An actual overrun records debt
and signals overrun but cannot undo an already-billed call. Fixed-window accounting
is based on admission time, not the provider's invoice period.

There is an Ollama final-usage normalizer for native generate/chat metadata;
other provider clients need a reviewed application adapter. The SDK never parses
or stores prompts/outputs to meter usage. This does not change WebDecoy plans or
create a subscription meter.

## Optional browser evidence

Add `data-runtime-evidence="true"` to the existing WebDecoy scanner tag and set
`BrowserEvidenceOrigin` to the exact HTTPS site origin (no trailing slash).
Requires the compatible ingest/CDN deployment and a same-origin AI endpoint.
The SDK forwards only the property-specific WebDecoy receipt, never the other
cookies. The signed observation expires after 60 seconds and is bound to the
property, origin, IP and user agent. Missing or invalid evidence fails open and
adds an unavailable `browser_evidence` check; a clean receipt never overrides
another denial. This is optional risk evidence, not proof of a human or identity.
Start in observe mode; real-world accuracy has not been established.

`Protect` selects the receipt from the incoming HTTP request automatically.
With `Check`, pass request Headers or the explicit Request.BrowserEvidence value.

## Model-attempt reports

Budget hooks now send separate start/finish events to WebDecoy automatically.
Each attempt has a random call ID; pass the admission decision's request ID in
`BudgetCall.RequestID` (`decision.ID()`). `BudgetResult.CallID` exposes the attempt ID.
Drain model work then call `Client.Flush(ctx)` to flush both report types.

The dashboard labels callback starts and final usage as SDK-reported and joins
retained reservations to confirm accounting. Neither is a provider invoice.
Missing usage is unknown, and avoided cost is unavailable—not inferred from
request denials. Usage events contain numeric tokens, configured rates and price/
rule codes, but no prompts, responses, model names or raw user identities. Use
non-sensitive price/rule codes. Reporting remains bounded and best effort;
failures do not change provider results, trigger retries or refund charges.
Requires the compatible usage endpoint; old backends may log reporting failures.

## Release contract

Minimum supported Go toolchain: 1.26.1; tested with that exact toolchain. The module
has zero third-party dependencies. `scripts/check-module.py` builds an explicit
allowlist zip and installs it into a fresh consumer and module cache using a local
file proxy; it does not publish a module or contact a public checksum service.
The ephemeral proxy test disables sumdb only for that locally generated fixture;
do not copy those settings to customer builds. The public alpha is licensed under Apache-2.0. Use the tagged module version
without a local replace directive in customer builds.

Config/detector JSON is capped at 64 KiB. Detector and reporting timeouts default
to one second and are limited to ten seconds; report capacity defaults to 100 and
is limited to 10000. Standard net/http transport honors request context; a supplied
custom transport must do so too. A normalized Route is required (maximum 512 bytes,
no query/fragment). The SDK never parses untrusted forwarding headers into client IP.

Basic cold/warm cloud admission permits up to two/one seconds of configured waits.
Optional quota, lease acquire and per-call reservation each default to one more
second. Rule CPU, caller auth/IP resolution, scheduling, model work and custom
transports are outside this bound. Do not describe it as a wall-clock SLA.
Drain HTTP/model work on shutdown and then Flush with a deadline. Existing callback
streaming/writer interfaces are passed through; flushing cannot recover lost reports.

### Recovering an uncertain quota admission (opt-in)

Set `AccountQuota.Idempotency: true` only after quota schema 2 is deployed.
The SDK creates one operation ID and retries the quota RPC at most once after
transport/5xx/malformed-response failures using the same payload. `Timeout` is per
attempt (up to twice that duration overall). Cancellation stops retries; HTTP 4xx
stops retries. There is no fallback to schema 1; legacy options keep single-attempt
schema-1 behavior.

For recovery across requests/processes, persist `NewQuotaOperationID()` in trusted
server state and supply `OperationID func(T) string`. `Decision.Checks()` exposes
the local quota check's `OperationID`; central report JSON omits it. Never trust a
browser-selected ID or reuse an ID for a different logical operation.

IDs expire after ten minutes, with at most 30 seconds forward clock skew. Expired
IDs cannot consume again after receipt cleanup. Capacity is 10,000 retained
operations/property, including denials. Same-payload replays return the original
quota decision; conflicting payloads are rejected. Unresolved results have reason
`account_quota_outcome_unknown`; existing open/closed settings still apply. Do not
mint a new ID blindly to recover an expired unknown operation. Replay counts and
retry hints describe the original quota window.

This deduplicates admission, not execution of application/model callbacks. The hosted runtime must support quota schema 2 before opting in.

## Action authorization (unreleased development preview)

The source checkout includes `NewActionProtection` for authenticated local action
dispatch. It is not in the published `v0.1.0-alpha.2` tag. See the
[record-action example](examples/actions/README.md) for server authentication,
permission checks, execution ownership, cancellation and evidence limits.
