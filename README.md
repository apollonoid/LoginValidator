# LoginValidator

# Security Event Processing System (Go)

This project processes login events in real time and detects suspicious behavior such as brute-force attempts.

## Features
- Event ingestion (JSON)
- Redis storage
- Rule-based detection
- Prometheus metrics
- (WIP) Grafana dashboards

## Status
Work in progress

# Event Schema

{
  "event_id": "uuid",
  "event_type": "auth",
  "outcome": "success | failure",
  "user_id": "string",
  "source_ip": "string",
  "user_agent": "string",
  "timestamp": "RFC3339"
}
