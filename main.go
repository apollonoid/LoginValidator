package main

import (
	"os"

	"github.com/apollonoid/LoginValidator/detection"
	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/apollonoid/LoginValidator/redis"
)

func main() {
	domain.InitLogger()
	pipeline.InitPipeline()
	detection.InitRules(envOrDefault("LOGIN_VALIDATOR_RULES_PATH", "rules.yaml"), envOrDefault("LOGIN_VALIDATOR_METRICS_ADDR", ":2112"))
	redis.InitRedis(envOrDefault("LOGIN_VALIDATOR_REDIS_ADDR", "127.0.0.1:6379"))
	jsonapi.ListenAndServe(envOrDefault("LOGIN_VALIDATOR_HTTP_ADDR", ":8080"))
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
