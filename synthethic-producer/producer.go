package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/google/uuid"
	"github.com/mroth/weightedrand/v2"
)

func main() {
	url := "http://localhost:8080/events"
	for {
		event := generateEvent()
		jsonEvent, err := json.Marshal(event)
		if err != nil {
			log.Println("Failed to Marshal event: ", err)
			continue
		}
		body := bytes.NewReader(jsonEvent)
		req, err := http.NewRequest("POST", url, body)
		if err != nil {
			log.Println("Failed to create request:", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println("Request failed:", err)
		} else {
			log.Println("SENT:", string(jsonEvent), "STATUS:", resp.Status)
			resp.Body.Close()
		}
		time.Sleep(20 * time.Second)
	}
}

func generateEvent() domain.Event {
	uuid := uuid.New()
	eventType := "auth"
	successfulRand, err := weightedrand.NewChooser(
		weightedrand.NewChoice(domain.Outcome(true), 9),
		weightedrand.NewChoice(domain.Outcome(false), 1),
	)
	successful := successfulRand.Pick()
	if err != nil {
		successful = domain.Outcome(false)
	}
	id := rand.Intn(10)
	userId := "user_" + strconv.Itoa(id)
	if err != nil {
		userId = "user_0"
	}
	sourceIpRand, err := weightedrand.NewChooser(
		weightedrand.NewChoice("85.23.44.83", 2),
		weightedrand.NewChoice("125.133.22.4", 6),
		weightedrand.NewChoice("145.14.1.133", 2),
	)
	sourceIp := sourceIpRand.Pick()
	if err != nil {
		sourceIp = "85.23.44.83"
	}
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	timestamp := time.Now()
	return domain.Event{
		EventID:    uuid,
		EventType:  eventType,
		Successful: successful,
		UserID:     userId,
		SourceIP:   sourceIp,
		UserAgent:  userAgent,
		Timestamp:  timestamp,
	}
}
