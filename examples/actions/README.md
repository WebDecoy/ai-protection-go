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
streams, detached work, shared operation allowances and MCP dispatch are follow-ups.

Errors propagate without retry. Cancellation or errors after dispatch have unknown
side-effect outcomes. Panic during admission denies; execution panic is recorded as
unknown and rethrown. Local observer events exclude raw identity/arguments/results;
up to 100 observer goroutines are allowed, then events are dropped. Delivery order
is not guaranteed; correlate by action ID and outcome. This is best-effort local
telemetry, not hosted reporting or a complete audit trail.
