package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiveness(t *testing.T) {
	h := NewHealth("auth-service")
	rec := httptest.NewRecorder()
	h.Liveness(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field: got %q", body["status"])
	}
}

func TestReadiness_degraded(t *testing.T) {
	h := NewHealth("auth-service",
		stubChecker{name: "postgres", err: errors.New("down")},
		stubChecker{name: "redis"},
	)

	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", rec.Code)
	}
}

type stubChecker struct {
	name string
	err  error
}

func (s stubChecker) Name() string                      { return s.name }
func (s stubChecker) Ping(_ context.Context) error     { return s.err }
