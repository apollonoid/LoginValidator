package redis

import (
	"context"
	"log"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/redis/go-redis/v9"
)

var Rdb *redis.Client
var Ctx context.Context

func InitRedis() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	Ctx = context.Background()
	pingCtx, cancel := context.WithTimeout(Ctx, 2*time.Second)
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
	key := "event:" + event.EventID.String()
	cmd := Rdb.HSet(Ctx,
		key,
		"event_id", event.EventID.String(),
		"event_type", event.EventType,
		"outcome", bool(event.Successful),
		"user_id", event.UserID,
		"source_ip", event.SourceIP,
		"user_agent", event.UserAgent,
		"timestamp", event.Timestamp.Unix(),
	)
	// Default expiration of 10 minutes
	Rdb.Expire(Ctx, key, 10*time.Minute)
	if err := cmd.Err(); err != nil {
		log.Println("Redis HSet error:", err)
	}
}
