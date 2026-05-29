package password

import "testing"

func TestHashAndCompare(t *testing.T) {
	hash, err := Hash("secret-password", 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(hash, "secret-password"); err != nil {
		t.Fatal("expected match")
	}
	if Compare(hash, "wrong") == nil {
		t.Fatal("expected mismatch")
	}
}
