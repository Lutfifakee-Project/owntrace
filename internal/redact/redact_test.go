package redact

import (
	"strings"
	"testing"
)

func TestSensitiveHeaderRedaction(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "X-API-Key", "api-key"} {
		got := HeaderValue(name, "super-secret-value-123")
		if got == "super-secret-value-123" {
			t.Errorf("header %s value leaked", name)
		}
		if !strings.HasPrefix(got, Marker) {
			t.Errorf("header %s: expected marker, got %q", name, got)
		}
	}
	if got := HeaderValue("Content-Type", "application/json"); got != "application/json" {
		t.Errorf("non-sensitive header altered: %q", got)
	}
}

func TestJWTScrubbing(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
	body := `{"token": "` + jwt + `", "name": "x"}`
	got := Text(body)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Fatalf("JWT leaked in text: %s", got)
	}
	if !strings.Contains(got, Marker) {
		t.Errorf("expected redaction marker, got %s", got)
	}
}

func TestFingerprintStability(t *testing.T) {
	a := Value("secret-abc")
	b := Value("secret-abc")
	c := Value("secret-xyz")
	if a != b {
		t.Error("fingerprint of same value differs")
	}
	if a == c {
		t.Error("fingerprints of different values collide")
	}
}

func TestJSONBodyRedaction(t *testing.T) {
	in := map[string]any{
		"username":     "alice",
		"password":     "hunter2-hunter2",
		"access_token": "tok-abcdef-0123456789",
		"nested":       map[string]any{"api_key": "key-1234567890abcdefKEY"},
		"list":         []any{"ok", "password-hunter2-hunter2"},
	}
	out := JSONBody(in)
	m := out.(map[string]any)
	if m["password"] == "hunter2-hunter2" {
		t.Error("password leaked")
	}
	if m["access_token"] == "tok-abcdef-0123456789" {
		t.Error("access_token leaked")
	}
	nested := m["nested"].(map[string]any)
	if nested["api_key"] == "key-1234567890abcdefKEY" {
		t.Error("api_key leaked")
	}
	if m["username"] != "alice" {
		t.Errorf("non-sensitive field altered: %v", m["username"])
	}
}

func TestURLRedaction(t *testing.T) {
	got := URL("https://user:pass@example.com/path?token=tok1234567890&q=hello")
	if strings.Contains(got, "pass") && !strings.Contains(got, Marker) {
		t.Errorf("userinfo leaked: %s", got)
	}
	if strings.Contains(got, "tok1234567890") {
		t.Errorf("token query param leaked: %s", got)
	}
	if !strings.Contains(got, "q=hello") {
		t.Errorf("non-sensitive param altered: %s", got)
	}
}

func TestEmailPII(t *testing.T) {
	got := Text("contact jane.doe@example.com for details")
	if strings.Contains(got, "jane.doe@example.com") {
		t.Errorf("PII email leaked: %s", got)
	}
}

func TestBodyForEvidence(t *testing.T) {
	in := []byte(`{"session": "sess-tok-12345678901234567890", "data": {"id": 1}}`)
	got := BodyForEvidence("application/json", in)
	if strings.Contains(got, "sess-tok-12345678901234567890") {
		t.Errorf("session token leaked: %s", got)
	}
	if !strings.Contains(got, `"id"`) {
		t.Errorf("structure lost: %s", got)
	}
}
