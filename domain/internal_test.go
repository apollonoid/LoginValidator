package domain

import (
	"encoding/json"
	"testing"
)

func TestOutcomeUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Outcome
	}{
		{name: "success", body: `"success"`, want: Success},
		{name: "failure", body: `"failure"`, want: Failure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Outcome
			if err := json.Unmarshal([]byte(tt.body), &got); err != nil {
				t.Fatalf("json.Unmarshal returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("outcome = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOutcomeUnmarshalJSONRejectsUnknownValue(t *testing.T) {
	var outcome Outcome
	if err := json.Unmarshal([]byte(`"pending"`), &outcome); err == nil {
		t.Fatal("json.Unmarshal returned nil error for invalid outcome")
	}
}

func TestOutcomeMarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		outcome Outcome
		want    string
	}{
		{name: "success", outcome: Success, want: `"success"`},
		{name: "failure", outcome: Failure, want: `"failure"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.outcome)
			if err != nil {
				t.Fatalf("json.Marshal returned error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("json = %s, want %s", got, tt.want)
			}
		})
	}
}
