package domain

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	EventID    uuid.UUID `json:"event_id"`
	EventType  string    `json:"event_type"`
	Successful Outcome   `json:"outcome"`
	UserID     string    `json:"user_id"`
	SourceIP   string    `json:"source_ip"`
	UserAgent  string    `json:"user_agent"`
	Timestamp  time.Time `json:"timestamp"`
}

type Outcome bool

const (
	Failure Outcome = false
	Success Outcome = true
)

var fileLogger *log.Logger

func InitLogger() {
	logPath := os.Getenv("LOGIN_VALIDATOR_LOG_PATH")
	if logPath == "" {
		logPath = "login_validator.log"
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		log.Fatalf("Failed to prepare log directory: %v", err)
	}
	file, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0666,
	)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	fileLogger = log.New(
		file,
		"",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
}

func Alert(message string) {
	if fileLogger == nil {
		log.Println("ALERT:", message)
		return
	}
	fileLogger.Println("ALERT:", message)
}

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

func (o Outcome) MarshalJSON() ([]byte, error) {
	switch o {
	case true:
		return json.Marshal("success")
	case false:
		return json.Marshal("failure")
	default:
		return nil, fmt.Errorf("invalid outcome value: %v", o)
	}
}
