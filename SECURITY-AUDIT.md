# SEMP Security Audit Report

**Date:** April 2026
**Scope:** Protocol implementation (semp-go v0.3.0, semp-reference-server, semp-reference-client)
**Auditor:** Automated structural review.

---

## Summary

| Audit | High | Medium | Low | Info |
|-------|------|--------|-----|------|
| 1. Denial of Service | 2 | 4 | 2 | 0 |
| 2. Privacy Leakage | 1 | 2 | 2 | 0 |
| 3. Federation Trust | 1 | 2 | 1 | 0 |
| 4. Concurrency | 0 | 2 | 2 | 0 |
| 5. Input Validation | 1 | 2 | 2 | 0 |
| 6. Error Handling | 0 | 3 | 2 | 0 |
| 7. Dependencies | 0 | 0 | 0 | 2 |
| 8. SQL Injection | 0 | 0 | 0 | 4 |
| 9. TLS Configuration | 0 | 1 | 3 | 2 |
| **Total** | **5** | **16** | **13** | **8** |

---

## High Findings

### 1.1 No HTTP body size limits
POST handlers for /v1/register, /v1/blocklist, /v1/device/register read unbounded request bodies.
**Fix:** Wrap r.Body with http.MaxBytesReader before decoding.

### 1.2 Unbounded inbox queue
In-memory Inbox has no per-user or global size limit. Can grow until OOM.
**Fix:** Add configurable max queue depth per address. Reject when full.

### 2.1 User enumeration via register
Different error codes for "unknown user" (403) vs "wrong password" (401).
**Fix:** Return identical error for both cases.

### 3.1 TrustingDomainVerifier
Federation responder accepts any domain claim without verification.
**Fix:** Verify peer domain via well-known domain key fetch or DNS.

### 5.1 Same as 1.1
No body size limits on POST handlers.

---

## Clean Audits

### SQL Injection: No issues found
All queries use parameterized placeholders consistently.

### Dependencies: Current
All direct dependencies at current versions with no known CVEs.

---

## Positive Findings

- WebSocket enforces max message size via SetReadLimit
- TLS is correctly enforced for QUIC (TLS 1.3 minimum)
- Dial functions refuse non-TLS URLs unless AllowInsecure is set
- InsecureSkipVerify only used in test files
- SQL queries consistently parameterized
- Base64 decode errors handled properly (no panics)
- Envelope canonical form is deterministic
