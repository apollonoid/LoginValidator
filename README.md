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
