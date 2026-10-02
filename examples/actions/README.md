# Local action boundary — unreleased preview

Run `go run ./examples/actions`. One authorized read executes; cross-tenant read,
export and forged-session attempts deny before dispatch. No model/network calls.

Use `NewActionProtection` with a server-owned registry and an `Authenticate` hook
that verifies your existing session/token. The fixture session is not a production
identity system. Authentication returns subject, tenant, issuer, expiry, scopes and
optional OAuth client ID. It does not establish agent signer identity or delegation.

Every action needs validation and application authorization. Policy can only
restrict. There is no detector fail-open override for permission errors. Arguments
are bounded raw JSON (16 KiB, depth 12, 2048 values); duplicate/dangerous object keys
are rejected. Hooks receive independent copies of caller scopes and arguments.
Never mutate authentication state concurrently; resolve a snapshot in your verifier.

Admission defaults to one second, max ten seconds. Up to 32 admission workers may
remain active. Hooks should honor context cancellation; a stuck hook occupies its
slot until it returns, and saturation denies with 503. Late results cannot execute
an action. The actual callback runs on the caller context, must await all work and
must enforce resource ownership in the actual database query/transaction. Live
streams, detached work, weighted operation allowances and MCP dispatch are follow-ups.

Errors propagate without retry. Cancellation or errors after dispatch have unknown
side-effect outcomes. Panic during admission denies; execution panic is recorded as
unknown and rethrown. Local observer events exclude raw identity/arguments/results;
up to 100 observer goroutines are allowed, then events are dropped. Delivery order
is not guaranteed; correlate by action ID and outcome. This is best-effort local
telemetry. Optional hosted reporting is described below.

## Shared limits and hosted evidence (source preview)

Set `ActionOptions.SharedRuntime` to connect the action boundary to AI Protection:

```go
SharedRuntime: &aiprotection.ActionRuntime{
    BaseURL: "https://ai-protection.webdecoy.com",
    APIKey: serverPropertyKey,
    PropertyID: propertyID,
    SubjectSecret: secretSharedAcrossReplicas, // >=32 UTF-8 bytes
},
```

Each `ActionDefinition` may then set `Limits`:

```go
Limits: &aiprotection.ActionLimits{
    CallerQuota: &aiprotection.ActionQuota{
        RuleID: "record_read_caller", Limit: 100, WindowSeconds: 60,
        Mode: aiprotection.Enforce, FailureMode: aiprotection.Closed,
    },
    TenantQuota: &aiprotection.ActionQuota{
        RuleID: "record_read_tenant", Limit: 1000, WindowSeconds: 60,
        Mode: aiprotection.Enforce, FailureMode: aiprotection.Closed,
    },
    Concurrency: &aiprotection.ActionConcurrency{
        RuleID: "record_read_work", AccountLimit: 2, FeatureLimit: 20,
        TTLSeconds: 30, MaxSeconds: 300,
        Mode: aiprotection.Enforce, FailureMode: aiprotection.Closed,
    },
},
```

Rule IDs must be distinct across the registry. Shared checks happen after local
permissions. Caller quotas bind issuer, tenant and subject; tenant quotas bind the
canonical tenant across issuers. Identity hashing is compatible with the Node SDK;
matching property, secret, rule IDs and settings share allowances across runtimes.
Canonical tenant IDs must come from trusted application membership checks.

Shared controls default to observe/open; choose enforce/closed for hard limits.
The local admission deadline covers authentication/permissions; shared RPCs have
separate bounded timeouts. Earlier quota consumption is not refunded on later
rejection. These are fixed request counts, not weighted work or retry-safe operation
reservations. Tool work never retries automatically.

The lease context cancels on renewal failure, caller cancellation or maximum work
time. The callback must honor that context and await all work. Errors, panics and
cancellation retain uncertain leases. A failed release after completed work preserves
the original result and records a degraded `concurrency_release` check.

Shared runtime configuration also sends bounded schema-2 events to the hosted AI
Protection dashboard. Events carry unique event IDs and correlated action IDs,
policy version, decisions and attempt/completion/unknown phases. Raw identity,
arguments, outputs, tokens and lease IDs are excluded. Events may be lost or arrive
out of order; they do not prove a complete execution history. Drain handlers, then
call `guard.Flush(ctx)` at shutdown. A reporting failure never reruns tool work.

This source preview is not included in the published `v0.1.0-alpha.2` tag.
