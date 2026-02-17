package redis

import (
	"context"
	"log"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/redis/go-redis/v9"
)

var Rdb *redis.Client
var ctx context.Context

func InitRedis() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	ctx = context.Background()
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := Rdb.Ping(pingCtx).Err(); err != nil {
		log.Fatalf("Redis unavailable at %s: %v", Rdb.Options().Addr, err)
		Rdb = nil
		return
	}
	log.Println("Redis listening on", Rdb.Options().Addr)
}

func StoreEvent(event domain.Event) {
	if Rdb == nil {
		return
	}
	log.Println("Storing event", event.EventID)
	cmd := Rdb.HSet(ctx,
		"event:"+event.EventID.String(),
		"event_id", event.EventID.String(),
		"event_type", event.EventType,
		"outcome", bool(event.Successful),
		"user_id", event.UserID,
		"source_ip", event.SourceIP,
		"user_agent", event.UserAgent,
		"timestamp", event.Timestamp.Unix(),
	)
	if err := cmd.Err(); err != nil {
		log.Println("Redis HSet error:", err)
	}
}
