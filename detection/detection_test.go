package detection

import (
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
	path := writeRulesFile(t, `
rapid_successful_login:
  threshold: 8
  window: nope
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

	if _, err := LoadRules(path); err == nil {
		t.Fatal("LoadRules returned nil error for invalid duration")
	}
}

func TestLoadRulesRejectsInvalidThreshold(t *testing.T) {
	path := writeRulesFile(t, `
  rapid_successful_login:
    threshold: 6
    window: 1m
  bruteforce_login_short:
    threshold: -20
    window: 1m
  bruteforce_login_long:
    threshold: 60
    window: 5m
  credential_stuffing:
    threshold: 5
    window: 30s
	`)

	if _, err := LoadRules(path); err == nil {
		t.Fatal("LoadRules returned nil error for negative threshold")
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
