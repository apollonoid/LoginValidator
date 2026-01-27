# LoginValidator

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