package jsonapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/pipeline"
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

func TestHandleEventAcceptsAuthEvent(t *testing.T) {
	events := make(pipeline.IngestionChannel, 1)
	handler := &Handler{IngestChan: events}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validAuthEventJSON))

	handler.HandleEvent(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
	}

	select {
	case event := <-events:
		if event.EventType != "auth" {
			t.Fatalf("event type = %q, want auth", event.EventType)
		}
		if event.UserID != "user_1" {
			t.Fatalf("user id = %q, want user_1", event.UserID)
		}
	default:
		t.Fatal("handler did not enqueue auth event")
	}
}

func TestHandleEventAcceptsButIgnoresNonAuthEvent(t *testing.T) {
	events := make(pipeline.IngestionChannel, 1)
	handler := &Handler{IngestChan: events}
	recorder := httptest.NewRecorder()
	body := strings.Replace(validAuthEventJSON, `"event_type": "auth"`, `"event_type": "healthcheck"`, 1)
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))

	handler.HandleEvent(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	if len(events) != 0 {
		t.Fatalf("queued events = %d, want 0", len(events))
	}
}

func TestHandleEventRejectsInvalidJSON(t *testing.T) {
	events := make(pipeline.IngestionChannel, 1)
	handler := &Handler{IngestChan: events}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(`{`))

	handler.HandleEvent(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if len(events) != 0 {
		t.Fatalf("queued events = %d, want 0", len(events))
	}
}

func TestHandleEventRejectsUnsupportedMethod(t *testing.T) {
	events := make(pipeline.IngestionChannel, 1)
	handler := &Handler{IngestChan: events}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/events", nil)

	handler.HandleEvent(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEventReturnsTooManyRequestsWhenPipelineIsFull(t *testing.T) {
	events := make(pipeline.IngestionChannel, 1)
	events <- domain.Event{}
	handler := &Handler{IngestChan: events}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validAuthEventJSON))

	handler.HandleEvent(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
}
