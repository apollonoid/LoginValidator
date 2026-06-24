package main

import (
	"log"
	"os"

	"github.com/apollonoid/LoginValidator/detection"
	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/apollonoid/LoginValidator/redis"
)

func main() {
	domain.InitLogger()

	rules, err := detection.LoadRules(envOrDefault("LOGIN_VALIDATOR_RULES_PATH", "rules.yaml"))
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}

	redisClient, err := redis.NewClient(envOrDefault("LOGIN_VALIDATOR_REDIS_ADDR", "127.0.0.1:6379"))
	if err != nil {
		log.Fatalf("failed to initialize redis: %v", err)
	}

	processor := detection.NewProcessor(*rules, redisClient)
	detection.StartMetricsServer(envOrDefault("LOGIN_VALIDATOR_METRICS_ADDR", ":2112"))
	pipeline.InitPipeline(processor.Analyze)
	jsonapi.ListenAndServe(envOrDefault("LOGIN_VALIDATOR_HTTP_ADDR", ":8080"))
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
