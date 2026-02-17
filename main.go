package main

import (
	"github.com/apollonoid/LoginValidator/jsonapi"
	"github.com/apollonoid/LoginValidator/pipeline"
	"github.com/apollonoid/LoginValidator/redis"
)

func main() {
	pipeline.InitPipeline()
	redis.InitRedis()
	jsonapi.ListenAndServe(":8080")
}
