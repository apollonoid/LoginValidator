package jsonapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/pipeline"
)

type Handler struct {
	IngestChan pipeline.IngestionChannel
}

func (h *Handler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	event := domain.Event{}
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if event.EventType != "login_attempt" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	select {
	case h.IngestChan <- event:
		log.Println("Accepted event", event.EventID)
		w.WriteHeader(http.StatusAccepted)
	default:
		http.Error(w, "event pipeline overloaded", http.StatusTooManyRequests)
	}
}

func ListenAndServe(bind string) {
	handler := &Handler{pipeline.EventsChannel}
	http.HandleFunc("/events", handler.HandleEvent)
	log.Println("JSON API Server listening on", bind)
	err := http.ListenAndServe(bind, nil)
	if err != nil {
		log.Fatalf("JSON server error: %v", err)
	}
}
