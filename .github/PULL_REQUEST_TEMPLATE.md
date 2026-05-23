<!--
Thanks for contributing to semp-go.

If your change touches the wire format or normative behavior, the spec PR
on semp-dev/semp-spec should land first; link it under "Spec reference"
below. Library-only changes (helpers, refactors, bug fixes) can land
directly here.

Keep the description short. The Test plan and checklist are what we
actually read when reviewing.
-->

## Summary

<!-- 1-3 bullets describing what changed and why. -->

-

## Spec reference

<!--
Cite the spec section(s) this PR implements or touches. Examples:
- DELIVERY.md §3.2.5 (disposition authentication)
- KEY.md §10.3.5 step 6 (issuance flow)
- N/A -- pure library refactor / Go-side helper

If the change requires a spec change, link the semp-spec PR/commit:
- semp-dev/semp-spec#123
-->

## Type of change

- [ ] Bug fix (no API or wire change)
- [ ] New feature / helper (additive, backwards-compatible)
- [ ] Breaking change (signature change, behavior change, wire change)
- [ ] Documentation / README only
- [ ] Test or tooling only

## Test plan

<!-- What you ran. Honesty over completeness. -->

- [ ] `go build ./...` clean
- [ ] `go vet ./...` clean
- [ ] `go test -race ./...` passes locally
- [ ] New tests added for new behavior (cover the happy path and at least one rejection / error path where applicable)
- [ ] If this changes a state machine, the change has been exercised under `-race` with concurrent callers
- [ ] If this adds an HTTP handler, status codes have been pinned in tests

## Backwards compatibility

<!--
Note any signature changes, removed exports, or changed defaults.
Pre-1.0 the project tolerates minor breakage on minor bumps; we still
want it called out so reviewers and downstream callers see it.
-->

- [ ] No public API changes
- [ ] Public API change (described below)

<!-- If checked, describe the change and the upgrade path. -->

## Checklist

- [ ] PR title is short and descriptive
- [ ] Commit messages explain the motivation behind the change
- [ ] No `--no-verify` / `--no-gpg-sign` bypasses in the commits
- [ ] Stale `// TODO`s, dead branches, and debug prints have been pruned
