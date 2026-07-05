package redis

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	goredis "github.com/redis/go-redis/v9"
)

type Client struct {
	rdb *goredis.Client
	ctx context.Context
}

func NewClient(addr string) (*Client, error) {
	client := &Client{
		rdb: goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: "",
			DB:       0,
			Protocol: 2,
		}),
		ctx: context.Background(),
	}

	if err := client.waitForRedis(5, 2*time.Second); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis unavailable at %s: %w", client.rdb.Options().Addr, err)
	}

	log.Println("Redis listening on", client.rdb.Options().Addr)
	return client, nil
}

func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

func (c *Client) waitForRedis(attempts int, timeout time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		pingCtx, cancel := context.WithTimeout(c.ctx, timeout)
		err := c.rdb.Ping(pingCtx).Err()
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

func (c *Client) StoreEvent(event domain.Event) {
	if c == nil || c.rdb == nil {
		return
	}
	key := "event:" + event.EventID.String()
	cmd := c.rdb.HSet(c.ctx,
		key,
		"event_id", event.EventID.String(),
		"event_type", event.EventType,
		"outcome", bool(event.Successful),
		"user_id", event.UserID,
		"source_ip", event.SourceIP,
		"user_agent", event.UserAgent,
		"timestamp", event.Timestamp.Unix(),
	)
	c.recordIP(event)
	c.rdb.Expire(c.ctx, key, 10*time.Minute)
	if err := cmd.Err(); err != nil {
		log.Println("Redis HSet error:", err)
	}
}

func (c *Client) AddSetMember(key, member string) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, fmt.Errorf("redis client is not initialized")
	}
	return c.rdb.SAdd(c.ctx, key, member).Result()
}

func (c *Client) SetExpiration(key string, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return fmt.Errorf("redis client is not initialized")
	}
	return c.rdb.Expire(c.ctx, key, ttl).Err()
}

func (c *Client) GetSetCardinality(key string) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, fmt.Errorf("redis client is not initialized")
	}
	return c.rdb.SCard(c.ctx, key).Result()
}

func (c *Client) GetSetMembers(key string) ([]string, error) {
	if c == nil || c.rdb == nil {
		return nil, fmt.Errorf("redis client is not initialized")
	}
	return c.rdb.SMembers(c.ctx, key).Result()
}

func (c *Client) IncrementCounter(key string) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, fmt.Errorf("redis client is not initialized")
	}
	return c.rdb.Incr(c.ctx, key).Result()
}

func (c *Client) recordIP(event domain.Event) {
	key := "user:" + event.UserID + ":ips"

	added, err := c.rdb.SAdd(c.ctx, key, event.SourceIP).Result()
	if err != nil {
		log.Println("Redis SAdd error:", err)
		return
	}
	if added == 1 {
		domain.Alert(fmt.Sprintf("Login detected from new IP %s for user %s", event.SourceIP, event.UserID))
	}
}
