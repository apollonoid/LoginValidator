# LoginValidator
Security Event Processing System (Go)

A backend system designed to process authentication events in real time and detect suspicious patterns such as brute-force login attempts.

## Overview
This project explores event-driven backend design, focusing on real-time ingestion, asynchronous processing, and rule-based detection.

## Features
- Real-time event ingestion using JSON payloads
- Redis-backed storage for event handling and state tracking
- Rule-based detection for identifying suspicious login behavior
- Prometheus metrics for observability
- (WIP) Grafana dashboards for monitoring and visualization

## Run with Docker

```bash
docker compose up --build
```

The API listens on `http://localhost:8080`, Prometheus metrics are exposed on `http://localhost:2112/metrics`, Prometheus is available at `http://localhost:9090`, and Grafana is available at `http://localhost:3000` with `admin` / `admin`.

Environment variables supported by the app:

- `LOGIN_VALIDATOR_REDIS_ADDR`
- `LOGIN_VALIDATOR_HTTP_ADDR`
- `LOGIN_VALIDATOR_METRICS_ADDR`
- `LOGIN_VALIDATOR_RULES_PATH`

## Smoke Test

After the stack is up, send a test event:

```bash
curl -i -X POST http://localhost:8080/events -H 'Content-Type: application/json' -d '{"event_id":"7fe23cfc-62d7-40ea-b80b-721c37b137ad","event_type":"auth","outcome":"success","user_id":"user_1","source_ip":"192.0.2.10","user_agent":"Mozilla/5.0","timestamp":"2026-05-04T12:00:00Z"}'
```

Expected result:

- HTTP `202 Accepted`
- event accepted by the ingestion endpoint

To stop the stack:

```bash
docker compose down
```

## Tech Stack
- Go (concurrency with goroutines)
- Redis
- Prometheus

## Event Flow
1. Events are ingested via JSON input
2. Events are stored and processed asynchronously
3. Detection rules analyze patterns (e.g., repeated failures)
4. Metrics are exposed for monitoring system behavior

## Event Schema
```json
{
  "event_id": "uuid",
  "event_type": "auth",
  "outcome": "success | failure",
  "user_id": "string",
  "source_ip": "string",
  "user_agent": "string",
  "timestamp": "RFC3339"
}
