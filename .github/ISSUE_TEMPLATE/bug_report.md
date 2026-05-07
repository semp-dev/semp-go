---
name: Bug report
about: A behavior in semp-go that does not match its documentation, the SEMP spec, or your reasonable expectation.
title: "[bug] "
labels: bug
assignees: ''
---

## What happened

<!-- One or two sentences. -->

## Reproduction

<!-- Smallest test or main.go that triggers it. Inline code is fine; a gist link works too. -->

```go
// minimal repro here
```

## Expected behavior

<!-- What you thought would happen, and ideally a spec citation if applicable (e.g., "DELIVERY.md §1.1.1.6 says receipts MUST be retained until ..."). -->

## Actual behavior

<!-- Output, error message, panic, stack trace, or wire dump. -->

## Environment

- `semp-go` version: <!-- run `go list -m semp.dev/semp-go` -->
- Go version: <!-- run `go version` -->
- OS / arch: <!-- e.g., darwin/arm64, linux/amd64 -->
- Crypto suite in use: <!-- baseline / pq / both, if relevant -->
- Transport in use: <!-- ws / h2 / quic / N/A -->

## Additional context

<!-- Anything else that helps diagnose: configuration, surrounding code, recent changes, etc. -->

## Checklist

- [ ] I have searched existing issues and this is not a duplicate.
- [ ] The reproduction is minimal (no unrelated code).
- [ ] I have included version + environment information.
- [ ] If this is a security issue, I have emailed `hello@semp.dev` instead of opening this issue.
