# Changelog

## v0.1.0-beta.0

First beta of the Go AI Protection SDK. The public API is unchanged from
`v0.1.0-alpha.4`; this release moves the module from alpha to beta.

- Add action lifecycle tests: an action admitted under one guard finishes under
  its original guard and `PolicyVersion` while a replacement guard with a new
  version applies to new requests, and a callback that consumes a stream inside
  `Execute` reports `completed` on success and `unknown` on error or
  cancellation, with cleanup running exactly once.
- Assert hosted action event outcomes for each lifecycle path
  (attempted/completed, not attempted, attempted/unknown on cancel or panic) and
  that all phases of one action share a correlated action ID.
- Document callback completion and policy replacement semantics in the actions
  example README.
- Update maturity labels and install instructions to `v0.1.0-beta.0`.

```sh
go get github.com/WebDecoy/ai-protection-go@v0.1.0-beta.0
```

Earlier alpha releases (`v0.1.0-alpha.1` through `v0.1.0-alpha.4`) are described
in the [GitHub releases](https://github.com/WebDecoy/ai-protection-go/releases).
