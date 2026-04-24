package reputation_test

import (
	"testing"

	"semp.dev/semp-go/reputation"
)

func TestBucketize(t *testing.T) {
	cases := []struct {
		in, want int64
	}{
		{0, 0},
		{-1, 0},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{100, 128},
		{1023, 1024},
		{1024, 1024},
		{1025, 2048},
		{1 << 19, 1 << 19},
		{(1 << 19) + 1, 1 << 20},
		{1 << 20, 1 << 20},
		{(1 << 20) + 1, 1 << 20}, // clamps to MaxMetricBucket
		{1 << 30, reputation.MaxMetricBucket},
	}
	for _, tc := range cases {
		got := reputation.Bucketize(tc.in)
		if got != tc.want {
			t.Errorf("Bucketize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
