package jsonapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Handler struct {
	IngestChan pipeline.IngestionChannel
}

var ingestRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "login_ingest_requests_total",
		Help: "Total number of login ingest requests observed by the API.",
	},
	[]string{"status"},
)

func (h *Handler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ingestRequestsTotal.WithLabelValues("method_not_allowed").Inc()
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	event := domain.Event{}
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		ingestRequestsTotal.WithLabelValues("invalid_json").Inc()
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if event.EventType != "auth" {
		ingestRequestsTotal.WithLabelValues("non_auth").Inc()
		w.WriteHeader(http.StatusAccepted)
		return
	}
	select {
	case h.IngestChan <- event:
		ingestRequestsTotal.WithLabelValues("accepted").Inc()
		pipeline.UpdateQueueDepth()
		w.WriteHeader(http.StatusAccepted)
	default:
		ingestRequestsTotal.WithLabelValues("overloaded").Inc()
		http.Error(w, "event pipeline overloaded", http.StatusTooManyRequests)
	}
}

func ListenAndServe(bind string) {
	ingestRequestsTotal.WithLabelValues("accepted").Add(0)
	ingestRequestsTotal.WithLabelValues("invalid_json").Add(0)
	ingestRequestsTotal.WithLabelValues("method_not_allowed").Add(0)
	ingestRequestsTotal.WithLabelValues("non_auth").Add(0)
	ingestRequestsTotal.WithLabelValues("overloaded").Add(0)

	handler := &Handler{pipeline.EventsChannel}
	http.HandleFunc("/events", handler.HandleEvent)
	log.Println("JSON API Server listening on", bind)
	err := http.ListenAndServe(bind, nil)
	if err != nil {
		log.Fatalf("JSON server error: %v", err)
	}
}
