package redis

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/redis/go-redis/v9"
)

var Rdb *redis.Client
var Ctx context.Context

func InitRedis(addr string) {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	Ctx = context.Background()
	if err := waitForRedis(5, 2*time.Second); err != nil {
		addr := Rdb.Options().Addr
		_ = Rdb.Close()
		Rdb = nil
		log.Fatalf("Redis unavailable at %s: %v", addr, err)
	}
	log.Println("Redis listening on", Rdb.Options().Addr)
}

func waitForRedis(attempts int, timeout time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		pingCtx, cancel := context.WithTimeout(Ctx, timeout)
		err := Rdb.Ping(pingCtx).Err()
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("Redis ping failed (attempt %d/%d): %v", i+1, attempts, err)
		time.Sleep(1 * time.Second)
	}
	return lastErr
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
	recordIP(event)
	Rdb.Expire(Ctx, key, 10*time.Minute)
	if err := cmd.Err(); err != nil {
		log.Println("Redis HSet error:", err)
	}
}

func recordIP(event domain.Event) {
	key := "user:" + event.UserID + ":ips"

	added, err := Rdb.SAdd(Ctx, key, event.SourceIP).Result()
	if err != nil {
		log.Println("Redis SAdd error:", err)
		return
	}
	if added == 1 {
		domain.Alert(fmt.Sprintf("Login detected from new IP %s for user %s", event.SourceIP, event.UserID))
	}
}
