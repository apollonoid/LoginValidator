package detection_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/apollonoid/LoginValidator/detection"
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	redisclient "github.com/apollonoid/LoginValidator/redis"
)

const validAuthEventJSON = `{
  "event_id": "7fe23cfc-62d7-40ea-b80b-721c37b137ad",
  "event_type": "auth",
  "outcome": "success",
  "user_id": "user_1",
  "source_ip": "192.0.2.10",
  "user_agent": "Mozilla/5.0",
  "timestamp": "2026-05-04T12:00:00Z"
}`

func TestHTTPToProcessorToRedisFlow(t *testing.T) {
	redisAddr, shutdownRedis := startRedisServer(t)
	t.Cleanup(shutdownRedis)

	client, err := redisclient.NewClient(redisAddr)
	if err != nil {
		t.Fatalf("failed to initialize redis client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("redis close returned error: %v", err)
		}
	})

	processor := detection.NewProcessor(detection.RuleConfig{
		RapidSuccessfulLogin: detection.Rule{Threshold: 2, WindowDuration: time.Minute},
		BruteforceLoginShort: detection.Rule{Threshold: 10, WindowDuration: time.Minute},
		BruteforceLoginLong:  detection.Rule{Threshold: 20, WindowDuration: 5 * time.Minute},
		CredentialStuffing:   detection.Rule{Threshold: 10, WindowDuration: time.Minute},
	}, client)

	events := make(pipeline.IngestionChannel, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		event := <-events
		processor.Analyze(event)
	}()

	server := httptest.NewServer(http.HandlerFunc((&jsonapi.Handler{IngestChan: events}).HandleEvent))
	t.Cleanup(server.Close)

	resp, err := http.Post(server.URL+"/events", "application/json", strings.NewReader(validAuthEventJSON))
	if err != nil {
		t.Fatalf("http post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for processor to finish")
	}

	cardinality, err := client.GetSetCardinality("successful_login:user_1")
	if err != nil {
		t.Fatalf("failed to read successful login set cardinality: %v", err)
	}
	if cardinality != 1 {
		t.Fatalf("successful login set cardinality = %d, want 1", cardinality)
	}

	members, err := client.GetSetMembers("successful_login:user_1")
	if err != nil {
		t.Fatalf("failed to read successful login set members: %v", err)
	}
	if len(members) != 1 || members[0] != "192.0.2.10" {
		t.Fatalf("successful login set members = %#v, want [192.0.2.10]", members)
	}
}

func startRedisServer(t *testing.T) (string, func()) {
	t.Helper()

	port := freeTCPPort(t)
	cmd := exec.Command(
		"redis-server",
		"--save", "",
		"--appendonly", "no",
		"--bind", "127.0.0.1",
		"--port", fmt.Sprint(port),
	)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Skipf("redis-server not available: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForRedisAddr(addr, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("redis-server failed to start at %s: %v\noutput:\n%s", addr, err, output.String())
	}

	return addr, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("network listeners are not available in this environment: %v", err)
		}
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForRedisAddr(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return context.DeadlineExceeded
}
