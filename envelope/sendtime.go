package envelope

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// DefaultSendTimeDelayCeiling is the RECOMMENDED upper bound on the
// random send-time delay per CLIENT.md section 3.8.1. Operators MAY
// configure a higher ceiling but SHOULD NOT exceed it by default.
const DefaultSendTimeDelayCeiling = 60 * time.Second

// SendTimeDelayConfig controls the behavior of SendTimeDelay.
type SendTimeDelayConfig struct {
	// Ceiling is the upper bound on the randomized delay. Actual
	// delay is drawn uniformly from [0, Ceiling]. Zero means no delay.
	Ceiling time.Duration

	// TimeSensitive, when true, skips the delay entirely. Clients
	// set this for envelopes the user has flagged as time-sensitive
	// (a verification code the user is actively reading, a reply in
	// a live conversation, etc.) per CLIENT.md section 3.8.1.
	TimeSensitive bool

	// NowFunc is a clock hook for tests. Defaults to time.Now.
	NowFunc func() time.Time
}

// SendTimeDelay sleeps for a random interval in [0, cfg.Ceiling] before
// returning, implementing the client-side send-time obfuscation from
// CLIENT.md section 3.8 (spec commit 3a9811d).
//
// SendTimeDelay respects cfg.TimeSensitive (returns immediately) and
// env.Postmark.Expires (reduces the drawn delay so submission does not
// push past the expiry window). Context cancellation returns
// ctx.Err() without additional wait.
//
// The mechanism reduces the temporal resolution available to a passive
// network observer correlating the sender's submission with the
// recipient's delivery. It does not hide correspondent pairs from
// either home server, does not defeat active adversaries, and is not
// a substitute for mixnet-class unlinkability.
func SendTimeDelay(ctx context.Context, env *Envelope, cfg SendTimeDelayConfig) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	if cfg.TimeSensitive || cfg.Ceiling <= 0 {
		return nil
	}
	nowFn := cfg.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}

	ceiling := cfg.Ceiling
	// Clamp the ceiling so the drawn delay cannot push submission
	// past postmark.expires. CLIENT.md section 3.8.1 requires that
	// "the delay MUST NOT push submission past postmark.expires".
	if !env.Postmark.Expires.IsZero() {
		window := env.Postmark.Expires.Sub(nowFn())
		if window <= 0 {
			return fmt.Errorf("envelope: cannot delay an already-expired envelope (expires %s)",
				env.Postmark.Expires.UTC().Format(time.RFC3339))
		}
		if window < ceiling {
			ceiling = window
		}
	}

	delay, err := randomDuration(ceiling)
	if err != nil {
		return fmt.Errorf("envelope: send-time random: %w", err)
	}
	if delay <= 0 {
		return nil
	}

	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// randomDuration returns a uniformly-random duration in [0, ceiling].
// Uses crypto/rand so the delay pattern is not predictable from prior
// draws.
func randomDuration(ceiling time.Duration) (time.Duration, error) {
	if ceiling <= 0 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	// Map the 64-bit random into [0, ceiling) via modulo. The slight
	// bias for non-power-of-two ceilings is acceptable: a bias of
	// 2^-64 over a delay range of seconds is invisible compared to
	// operating-system scheduler jitter.
	r := binary.BigEndian.Uint64(buf[:])
	return time.Duration(r % uint64(ceiling)), nil
}
