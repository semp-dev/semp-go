package keys

import "testing"

func TestComputeKnownVector(t *testing.T) {
	// SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	got := Compute([]byte("hello"))
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if string(got) != want {
		t.Errorf("Compute(\"hello\") = %s, want %s", got, want)
	}
}

func TestComputeEmpty(t *testing.T) {
	if got := Compute(nil); got != "" {
		t.Errorf("Compute(nil) = %q, want empty", got)
	}
	if got := Compute([]byte{}); got != "" {
		t.Errorf("Compute([]) = %q, want empty", got)
	}
}

func TestComputeDeterministic(t *testing.T) {
	a := Compute([]byte{1, 2, 3, 4, 5})
	b := Compute([]byte{1, 2, 3, 4, 5})
	if a != b {
		t.Errorf("Compute is non-deterministic: %s != %s", a, b)
	}
}

func TestComputeDistinct(t *testing.T) {
	a := Compute([]byte{1, 2, 3})
	b := Compute([]byte{1, 2, 4})
	if a == b {
		t.Errorf("Compute collision: %s == %s", a, b)
	}
}

func TestComputeLength(t *testing.T) {
	got := Compute([]byte("any input"))
	if len(got) != 64 {
		t.Errorf("fingerprint length = %d, want 64 hex chars", len(got))
	}
}
