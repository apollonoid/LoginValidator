package main

import (
	"github.com/apollonoid/LoginValidator/detection"
	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/apollonoid/LoginValidator/redis"
)

var cfg detection.RuleConfig

func main() {
	domain.InitLogger()
	pipeline.InitPipeline()
	detection.InitRules("rules.yaml")
	redis.InitRedis()
	jsonapi.ListenAndServe(":8080")
}
