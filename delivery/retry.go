package delivery

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Retry-schedule bounds per DELIVERY.md §2.3.
const (
	// MinRetryInitialInterval is the protocol-mandated minimum first
	// base interval for delivery retries.
	MinRetryInitialInterval = 60 * time.Second

	// MinRetryMultiplier is the minimum exponential backoff multiplier
	// between consecutive intervals.
	MinRetryMultiplier = 2.0

	// MaxRetryInterval caps individual inter-attempt intervals.
	MaxRetryInterval = 6 * time.Hour

	// MinRetryJitterFraction is the minimum jitter fraction j applied
	// symmetrically as a multiplier in [1-j, 1+j]. Operators MAY use
	// larger values; 0.25 is recommended for high-volume queues.
	MinRetryJitterFraction = 0.10

	// MinJitterFloor is the protocol-mandated lower bound on the
	// realized jittered interval: jitter MUST NOT reduce the realized
	// interval below 50% of MinRetryInitialInterval.
	MinJitterFloor = MinRetryInitialInterval / 2

	// MinRetryAttempts is the minimum number of retry attempts a
	// sending server MUST make before declaring terminal failure by
	// deadline (subject to deadline permitting).
	MinRetryAttempts = 5

	// DefaultMaxRetryHorizon is the default ceiling for
	// server_max_retry_horizon per DELIVERY.md §2.4.
	DefaultMaxRetryHorizon = 72 * time.Hour

	// MaxRetryHorizonCap is the hard ceiling on server_max_retry_horizon
	// (the spec MUST NOT-exceed bound).
	MaxRetryHorizonCap = 7 * 24 * time.Hour
)

// RetryConfig is the operator-configurable retry policy. Zero values
// fall back to spec minima. See DELIVERY.md §2.3.
type RetryConfig struct {
	// InitialInterval is the first base interval before any exponential
	// growth. Defaults to MinRetryInitialInterval (60s) when zero. Any
	// value below MinRetryInitialInterval is clamped up.
	InitialInterval time.Duration

	// Multiplier is the exponential backoff factor between consecutive
	// base intervals. Defaults to MinRetryMultiplier (2.0) when zero
	// or below MinRetryMultiplier; clamped up.
	Multiplier float64

	// MaxInterval caps individual base intervals before jitter.
	// Defaults to MaxRetryInterval (6h) when zero. Any larger value
	// is clamped down.
	MaxInterval time.Duration

	// JitterFraction j is the symmetric jitter half-width. Defaults
	// to MinRetryJitterFraction (0.10) when zero or below; clamped up.
	JitterFraction float64
}

// SanitizeRetry returns a copy of cfg with each field replaced by its
// effective value after applying the spec minima/maxima.
func SanitizeRetry(cfg RetryConfig) RetryConfig {
	out := cfg
	if out.InitialInterval < MinRetryInitialInterval {
		out.InitialInterval = MinRetryInitialInterval
	}
	if out.Multiplier < MinRetryMultiplier {
		out.Multiplier = MinRetryMultiplier
	}
	if out.MaxInterval <= 0 || out.MaxInterval > MaxRetryInterval {
		out.MaxInterval = MaxRetryInterval
	}
	if out.JitterFraction < MinRetryJitterFraction {
		out.JitterFraction = MinRetryJitterFraction
	}
	return out
}

// BaseInterval returns the unjittered base interval for the given
// zero-indexed attempt (attempt=0 is the first retry, attempt=1 the
// second, etc.). The base interval is InitialInterval *
// Multiplier^attempt, clamped to MaxInterval, and clamped from below
// to MinRetryInitialInterval (the 60s floor applies only on the
// first base interval per §2.3).
func BaseInterval(cfg RetryConfig, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	cfg = SanitizeRetry(cfg)
	d := float64(cfg.InitialInterval)
	for i := 0; i < attempt; i++ {
		d *= cfg.Multiplier
		if time.Duration(d) > cfg.MaxInterval {
			d = float64(cfg.MaxInterval)
			break
		}
	}
	out := time.Duration(d)
	if out > cfg.MaxInterval {
		out = cfg.MaxInterval
	}
	return out
}

// JitterInterval returns base scaled by a symmetric random multiplier
// in [1-j, 1+j], floored at MinJitterFloor (the 30s spec floor).
// Uses crypto/rand so the jitter pattern is not predictable across
// the queue.
func JitterInterval(cfg RetryConfig, base time.Duration) (time.Duration, error) {
	cfg = SanitizeRetry(cfg)
	if base <= 0 {
		return 0, errors.New("delivery: non-positive base interval")
	}
	// Draw a uniform random fraction in [0, 1).
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("delivery: jitter random: %w", err)
	}
	r := float64(binary.BigEndian.Uint64(buf[:])) / float64(^uint64(0))
	// Map to [1-j, 1+j].
	multiplier := (1.0 - cfg.JitterFraction) + 2.0*cfg.JitterFraction*r
	jittered := time.Duration(float64(base) * multiplier)
	if jittered < MinJitterFloor {
		jittered = MinJitterFloor
	}
	return jittered, nil
}

// NextAttempt returns the wall-clock time of the next attempt:
// previous + JitterInterval(BaseInterval(cfg, attempt)).
func NextAttempt(cfg RetryConfig, previous time.Time, attempt int) (time.Time, error) {
	if previous.IsZero() {
		return time.Time{}, errors.New("delivery: previous attempt time is zero")
	}
	base := BaseInterval(cfg, attempt)
	jittered, err := JitterInterval(cfg, base)
	if err != nil {
		return time.Time{}, err
	}
	return previous.Add(jittered), nil
}

// IsRecoverable reports whether the given reason code permits
// retry per DELIVERY.md §2.3 / ERRORS.md §3. Unknown reason codes
// default to non-recoverable.
func IsRecoverable(reasonCode string) bool {
	switch reasonCode {
	case "handshake_invalid",
		"handshake_expired",
		"no_session",
		"server_unavailable",
		"rate_limited",
		"server_at_capacity":
		return true
	default:
		return false
	}
}

// EffectiveDeadline returns the earlier of postmarkExpires and
// queuedAt + horizon, where horizon is clamped to
// DefaultMaxRetryHorizon when zero or to MaxRetryHorizonCap when
// larger than the spec ceiling. Per DELIVERY.md §2.4.
func EffectiveDeadline(postmarkExpires, queuedAt time.Time, horizon time.Duration) time.Time {
	if horizon <= 0 {
		horizon = DefaultMaxRetryHorizon
	}
	if horizon > MaxRetryHorizonCap {
		horizon = MaxRetryHorizonCap
	}
	horizonDeadline := queuedAt.Add(horizon)
	if postmarkExpires.IsZero() {
		return horizonDeadline
	}
	if postmarkExpires.Before(horizonDeadline) {
		return postmarkExpires
	}
	return horizonDeadline
}
