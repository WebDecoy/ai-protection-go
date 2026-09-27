# WebDecoy AI Protection for Go

Local application policies plus WebDecoy cloud detection for Go AI endpoints.
Zero third-party dependencies. Requires Go 1.26.1 or newer.

**Local alpha prototype. No public repository or module version has been published.**
License selection is pending; no open-source license is granted by this draft.
The intended module path is `github.com/WebDecoy/ai-protection-go`.

## Install locally

From a Go application such as lowering-tax/backend:

```sh
go mod edit -require=github.com/WebDecoy/ai-protection-go@v0.0.0
go mod edit -replace=github.com/WebDecoy/ai-protection-go=/absolute/path/to/webdecoy-ai-protection-go
go mod tidy
```

Run tidy after importing the module; it removes unused requirements. A `go get`
command will only work after the repository and a version have been published.
Do not commit a developer-specific replace directive to an application release.

## Integrate before inference

Create a shared client once at startup. The application's Go type supplies trusted
context to local rules; context is never serialized to WebDecoy.

```go
import protection "github.com/WebDecoy/ai-protection-go"

type UserContext struct { CanGenerate bool }

client, err := protection.New(protection.Config[UserContext]{
    BaseURL: ingestOrigin,
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
bodies, cookie/authentication values and application context. Choose non-sensitive
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
normalization. Backend account/config, detection and report endpoints must be
deployed before a real staging pilot. No lowering.tax code is changed by this repo.
