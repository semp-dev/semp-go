# Contributing to semp-go

Thanks for your interest in `semp-go`. This document describes how to file issues, propose changes, and get a pull request merged.

## Code of Conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to abide by its terms. Report concerns to `hello@semp.dev`.

## Where the boundary is

`semp-go` is a reference implementation of the SEMP protocol. The spec lives at https://github.com/semp-dev/semp-spec.

| Change type | File the issue / PR in |
|---|---|
| Wire-format change, normative-keyword change, new spec record | [`semp-spec`](https://github.com/semp-dev/semp-spec) first; this repo mirrors after |
| Library API addition or refinement that does not change the wire | this repo |
| Bug fix in `semp-go` | this repo |
| New Go-side helper / convenience that has no spec impact | this repo |

If you are not sure which side a change belongs on, open a [Question](https://github.com/semp-dev/semp-go/issues/new?template=question.md) -- we are happy to triage.

## Reporting bugs

Use the [Bug report](https://github.com/semp-dev/semp-go/issues/new?template=bug_report.md) template. Please include:

- The `semp-go` version (`go list -m semp.dev/semp-go`).
- Your Go version (`go version`).
- A minimal reproduction (the smallest test or `main.go` that reproduces).
- What you expected vs. what happened.
- Any relevant spec section.

## Suggesting changes

Use the [Feature request](https://github.com/semp-dev/semp-go/issues/new?template=feature_request.md) template for non-trivial work, or open a draft PR for small fixes.

For substantial changes, please open an issue first so we can align on direction before you spend time. The author tends to recommend an approach but presents alternatives; if you prefer a different shape, say so up front.

## Development setup

```sh
git clone https://github.com/semp-dev/semp-go
cd semp-go
go build ./...        # zero errors
go vet ./...          # zero findings
go test -race ./...   # all 25 packages pass
```

Go 1.25+ is required (the module uses `golang.org/x/crypto` v0.50+, which dropped support for older toolchains).

## Pull request expectations

Before opening a PR, make sure:

- `go build ./...` succeeds.
- `go vet ./...` is clean.
- `go test -race ./...` passes.
- Public API additions have godoc comments naming the spec section.
- New tests cover the change's main behavior, plus at least one rejection / error path where applicable.
- Spec citations are precise: `RECOVERY.md §5.1`, not "the recovery doc".
- For server-side state machines, use injectable clocks (`NowFn func() time.Time`) so tests are deterministic.
- Concurrency-sensitive code passes `go test -race`.
- Commits do not bypass hooks (`--no-verify`, `--no-gpg-sign`).

### Style

- Standard Go formatting (`gofmt`); no custom linters.
- Spec prose follows RFC-style normative language (MUST / SHOULD / MAY) when documenting a normative behavior.
- Use ASCII punctuation throughout. Keep code comments terse and let identifiers speak.

### Commits

A good commit message explains the motivation behind the change. The project's existing commits are descriptive; read recent ones for the house style. A typical commit message has:

1. A subject line under 72 characters.
2. A blank line.
3. One or more paragraphs describing the change, the spec reference, and any breaking implications.

The project does not require a CLA today.

### Test plan in the PR

Every PR's description should include a short Test plan section listing what you ran and what passed. The PR template has a checklist; fill it in honestly.

## Versioning

Pre-1.0 semver: minor bumps for meaningful additions or signature changes, patch bumps for bug fixes only. The library version is independent of the SEMP spec version it implements.

## Security disclosures

If you believe you have found a security issue, please email `hello@semp.dev` instead of filing a public issue. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
