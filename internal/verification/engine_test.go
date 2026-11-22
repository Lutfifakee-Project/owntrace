package verification

import (
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
)

// ex builds a synthetic exchange for classifier unit tests.
func ex(status int, body string) *httpclient.Exchange {
	return &httpclient.Exchange{
		Method:          "GET",
		RequestURL:      "http://api.test/x",
		Status:          status,
		Body:            body,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		At:              time.Now().UTC(),
	}
}

func TestEnginePickAttackerPrefersNonAdmin(t *testing.T) {
	// Empty manager: pickAttacker must fail clearly, not panic.
	m, err := auth.New(&config.Config{}, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Auth: m}
	if _, err := e.pickAttacker("nobody"); err == nil {
		t.Fatal("expected error when no profiles exist")
	}
}
