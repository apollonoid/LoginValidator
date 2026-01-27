package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	EventID   uuid.UUID `json:"event_id"`
	EventType string    `json:"event_type"`
	Outcome   Outcome   `json:"outcome"`
	UserID    string    `json:"user_id"`
	SourceIP  string    `json:"source_ip"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
}

type Outcome int

const (
	Failure Outcome = iota
	Success
)

func (o *Outcome) UnmarshalJSON(b []byte) error {
	s := string(b)

	switch s {
	case `"success"`:
		*o = Success
	case `"failure"`:
		*o = Failure
	default:
		return fmt.Errorf("invalid outcome: %s", s)
	}

	return nil
}
