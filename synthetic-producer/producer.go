package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/google/uuid"
	"github.com/mroth/weightedrand/v2"
)

const (
	defaultURL = "http://localhost:8080/events"

	steadyMinDelay = 100 * time.Millisecond
	steadyMaxDelay = 300 * time.Millisecond

	pressureWorkers   = 24
	pressureTick      = 10 * time.Millisecond
	pressureDuration  = 12 * time.Second
	recoveryDuration  = 3 * time.Second
	steadyCycleLength = 20 * time.Second
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	url := envOrDefault("LOGIN_VALIDATOR_PRODUCER_URL", defaultURL)
	client := &http.Client{Timeout: 5 * time.Second}

	log.Printf("synthetic producer targeting %s", url)

	for {
		runSteadyTraffic(client, url, steadyCycleLength)

		log.Println("phase: rapid-success burst")
		runBurstPhase(client, url, pressureWorkers, pressureDuration, generateRapidSuccessEvent)
		time.Sleep(recoveryDuration)

		log.Println("phase: bruteforce burst")
		runBurstPhase(client, url, pressureWorkers, pressureDuration, generateBruteforceEvent)
		time.Sleep(recoveryDuration)

		log.Println("phase: credential-stuffing burst")
		runBurstPhase(client, url, pressureWorkers, pressureDuration, generateCredentialStuffingEvent)
		time.Sleep(recoveryDuration)
	}
}

func runSteadyTraffic(client *http.Client, url string, duration time.Duration) {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		_ = sendEvent(client, url, generateMixedEvent())
		sleepWithJitter(steadyMinDelay, steadyMaxDelay)
	}
}

func runBurstPhase(client *http.Client, url string, workers int, duration time.Duration, makeEvent func(int) domain.Event) {
	deadline := time.Now().Add(duration)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for workerID := 0; workerID < workers; workerID++ {
		go func(id int) {
			defer wg.Done()
			ticker := time.NewTicker(pressureTick)
			defer ticker.Stop()

			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					_ = sendEvent(client, url, makeEvent(id))
				}

				if time.Now().After(deadline) {
					return
				}
			}
		}(workerID)
	}

	<-time.After(duration)
	close(stop)
	wg.Wait()
}

func generateMixedEvent() domain.Event {
	if rand.Intn(100) < 75 {
		return generateSuccessfulEvent(randomUserID(), randomIP())
	}
	return generateFailureEvent(randomUserID(), randomIP())
}

func generateRapidSuccessEvent(workerID int) domain.Event {
	userID := "user_rapid"
	ipPool := []string{
		"192.0.2.10",
		"192.0.2.11",
		"192.0.2.12",
		"192.0.2.13",
		"192.0.2.14",
		"192.0.2.15",
		"192.0.2.16",
		"192.0.2.17",
		"192.0.2.18",
		"192.0.2.19",
	}
	return generateSuccessfulEvent(userID, ipPool[workerID%len(ipPool)])
}

func generateBruteforceEvent(workerID int) domain.Event {
	sourceIPs := []string{
		"198.51.100.50",
		"198.51.100.51",
		"198.51.100.52",
	}
	return generateFailureEvent("user_"+strconv.Itoa(workerID%10), sourceIPs[workerID%len(sourceIPs)])
}

func generateCredentialStuffingEvent(workerID int) domain.Event {
	sourceIPs := []string{
		"203.0.113.80",
		"203.0.113.81",
		"203.0.113.82",
	}
	return generateFailureEvent("target_"+strconv.Itoa(workerID%20), sourceIPs[workerID%len(sourceIPs)])
}

func generateSuccessfulEvent(userID, sourceIP string) domain.Event {
	return domain.Event{
		EventID:    uuid.New(),
		EventType:  "auth",
		Successful: domain.Success,
		UserID:     userID,
		SourceIP:   sourceIP,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		Timestamp:  time.Now(),
	}
}

func generateFailureEvent(userID, sourceIP string) domain.Event {
	return domain.Event{
		EventID:    uuid.New(),
		EventType:  "auth",
		Successful: domain.Failure,
		UserID:     userID,
		SourceIP:   sourceIP,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		Timestamp:  time.Now(),
	}
}

func sendEvent(client *http.Client, url string, event domain.Event) error {
	jsonEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}

	body := bytes.NewReader(jsonEvent)
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return nil
}

func randomIP() string {
	sourceIPRand, err := weightedrand.NewChooser(
		weightedrand.NewChoice("85.23.44.83", 2),
		weightedrand.NewChoice("125.133.22.4", 6),
		weightedrand.NewChoice("145.14.1.133", 2),
	)
	if err != nil {
		return "85.23.44.83"
	}
	return sourceIPRand.Pick()
}

func randomUserID() string {
	return "user_" + strconv.Itoa(rand.Intn(10))
}

func sleepWithJitter(minDelay, maxDelay time.Duration) {
	if maxDelay <= minDelay {
		time.Sleep(minDelay)
		return
	}

	delta := maxDelay - minDelay
	time.Sleep(minDelay + time.Duration(rand.Int63n(int64(delta)+1)))
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
