package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRulesParsesConfiguredWindows(t *testing.T) {
	path := writeRulesFile(t, `
rapid_successful_login:
  threshold: 8
  window: 1m
bruteforce_login_short:
  threshold: 20
  window: 1m
bruteforce_login_long:
  threshold: 60
  window: 5m
credential_stuffing:
  threshold: 5
  window: 30s
`)

	cfg, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}

	assertRule(t, "rapid successful login", cfg.RapidSuccessfulLogin, 8, time.Minute)
	assertRule(t, "short bruteforce", cfg.BruteforceLoginShort, 20, time.Minute)
	assertRule(t, "long bruteforce", cfg.BruteforceLoginLong, 60, 5*time.Minute)
	assertRule(t, "credential stuffing", cfg.CredentialStuffing, 5, 30*time.Second)
}

func TestLoadRulesRejectsInvalidWindow(t *testing.T) {
	tests := []struct {
		name   string
		window string
	}{
		{
			name:   "negative",
			window: "-1m",
		},
		{
			name:   "zero",
			window: "0s",
		},
		{
			name:   "non-duration",
			window: "nope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeRulesFile(t, fmt.Sprintf(`
rapid_successful_login:
  threshold: 8
  window: %s
bruteforce_login_short:
  threshold: 20
  window: 1m
bruteforce_login_long:
  threshold: 60
  window: 5m
credential_stuffing:
  threshold: 5
  window: 30s
`, tt.window))

			if _, err := LoadRules(path); err == nil {
				t.Fatalf("LoadRules returned nil error for %s window", tt.name)
			}
		})
	}
}

func TestLoadRulesRejectsInvalidThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold string
	}{
		{
			name:      "negative",
			threshold: "-20",
		},
		{
			name:      "zero",
			threshold: "0",
		},
		{
			name:      "non-integer",
			threshold: "many",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeRulesFile(t, fmt.Sprintf(`
  rapid_successful_login:
    threshold: 6
    window: 1m
  bruteforce_login_short:
    threshold: %s
    window: 1m
  bruteforce_login_long:
    threshold: 60
    window: 5m
  credential_stuffing:
    threshold: 5
    window: 30s
	`, tt.threshold))

			if _, err := LoadRules(path); err == nil {
				t.Fatalf("LoadRules returned nil error for %s threshold", tt.name)
			}
		})
	}
}

func TestLoadRulesReturnsErrorForMissingFile(t *testing.T) {
	if _, err := LoadRules(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("LoadRules returned nil error for missing file")
	}
}

func writeRulesFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write rules file: %v", err)
	}
	return path
}

func assertRule(t *testing.T, name string, rule Rule, threshold int64, window time.Duration) {
	t.Helper()

	if rule.Threshold != threshold {
		t.Fatalf("%s threshold = %d, want %d", name, rule.Threshold, threshold)
	}
	if rule.WindowDuration != window {
		t.Fatalf("%s window = %s, want %s", name, rule.WindowDuration, window)
	}
}
