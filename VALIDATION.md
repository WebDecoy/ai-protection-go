# Go adapter validation — 2026-09-27

- Go 1.26.1 (matching lowering.tax's go.mod): `go test -race ./... -count=1`.
- Twelve tests cover local policy decisions, immutable decision evidence, metadata
  privacy, duplicate reporting, cloud observation/enforcement, outage fail-open,
  missing/mismatched account bindings, missing IPs, local rule panic/error policy,
  caller cancellation, unchanged request/writer and SSE flushing, bounded
  reporting, custom-sink isolation, concurrent account lookups/report delivery,
  expired account grants, detector timeout, redirect refusal and malformed config.
- `go vet ./...` passes; the local HTTP example compiles.
- In WebDecoy ingest, `TestAIProtectionGoSDKReportIntegration` runs this module in
  a separate Go process against the real HTTP report handler and verifies a
  local denial is stored in the database. Enable with WEBDECOY_GO_SDK_TEST_DIR.

Tests use synthetic accounts and model callbacks. No lowering.tax code, live
Anthropic calls, real customer traffic, deployment or publication is involved.
This establishes adapter/transport behavior, not production detection accuracy,
provider cancellation/billing behavior, or abuse-reduction value.

The live lowering.tax pilot still needs trusted ingress/IP resolution, an existing
WebDecoy property/key, compatible backend deployment, and integration after its
ownership/input validation and before SSE initialization and model invocation.
