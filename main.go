package main

import (
	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/apollonoid/LoginValidator/redis"
)

func main() {
	domain.InitLogger()
	pipeline.InitPipeline()
	redis.InitRedis()
	jsonapi.ListenAndServe(":8080")
}
