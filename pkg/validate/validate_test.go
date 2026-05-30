package validate

import "testing"

func TestIsSafeTextRejectsShellMeta(t *testing.T) {
	cases := []string{
		"user@example.com; rm -rf /",
		"user%3bwhoami@example.com",
		"$(whoami)@x.com",
		"user@example.com\n/bin/sh",
	}
	for _, s := range cases {
		if IsSafeText(s) {
			t.Fatalf("expected unsafe: %q", s)
		}
	}
}

func TestIsSafeTextAcceptsEmail(t *testing.T) {
	if !IsSafeText("user.name+tag@example.com") {
		t.Fatal("expected safe email")
	}
}

func TestIsSafePasswordAllowsSymbols(t *testing.T) {
	if !IsSafePassword("P@ssw0rd!|&;") {
		t.Fatal("password may contain shell-like symbols")
	}
	if IsSafePassword("pass\nword") {
		t.Fatal("expected newline rejected")
	}
}
