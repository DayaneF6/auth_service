package usecase

import "testing"

func TestNormEmail(t *testing.T) {
	if got := normEmail("  User@Example.COM "); got != "user@example.com" {
		t.Fatalf("got %q", got)
	}
}
