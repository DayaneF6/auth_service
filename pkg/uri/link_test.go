package uri

import "testing"

func TestActionLink(t *testing.T) {
	got, err := ActionLink("http://localhost:3000/verify", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://localhost:3000/verify?token=abc123" {
		t.Fatalf("got %q", got)
	}
}

func TestActionLinkRejectsJavascript(t *testing.T) {
	if _, err := ActionLink("javascript:alert(1)", "x"); err == nil {
		t.Fatal("expected error")
	}
}
