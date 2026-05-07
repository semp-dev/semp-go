---
name: Feature request
about: Propose a new helper, package, or API addition in semp-go that does NOT change the wire format.
title: "[feature] "
labels: enhancement
assignees: ''
---

## Problem

<!-- What you're trying to do, and why the existing API doesn't fit. One paragraph. -->

## Proposed solution

<!-- Sketch the API you'd like. A function signature or short interface is usually enough. -->

```go
// e.g., a proposed helper signature
```

## Alternatives considered

<!-- Other shapes you thought about, and why you ruled them out. -->

## Spec impact

<!-- Does this change require any spec change? If yes, this issue belongs on semp-spec first. -->

- [ ] This is a library-only change (no wire format, no normative behavior change).
- [ ] This requires a spec change first; tracking issue: <!-- link to semp-spec issue -->

## Backwards compatibility

<!-- Pre-1.0 the project tolerates minor breakage on minor bumps. Still, please note any signature change to existing public API. -->

## Checklist

- [ ] I have searched existing issues and this is not a duplicate.
- [ ] The proposed API is consistent with surrounding semp-go conventions (interfaces with in-memory ref impls, ctx-first, NowFn for testable clocks).
- [ ] I have considered whether this belongs on semp-spec instead.
