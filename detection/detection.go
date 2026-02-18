package detection

import (
	"fmt"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/redis"
)

func Analyze(event domain.Event) {
	redis.StoreEvent(event)
	detectFailedLogin(event, 8, 1*time.Minute)
}

// Detect multiple failed logins from the same ip
func detectFailedLogin(event domain.Event, threshold int64, window time.Duration) {
	if event.Successful != true {
		return
	}

	key := "fail:ip:" + event.SourceIP + event.UserID

	count, _ := redis.Rdb.Incr(redis.Ctx, key).Result()
	redis.Rdb.Expire(redis.Ctx, key, window)
	if count >= threshold {
		alert(
			fmt.Sprintf(
				"Multiple failed login attempts detected: %d attempts for user '%s' from IP %s within %s",
				count,
				event.UserID,
				event.SourceIP,
				window.String(),
			),
		)
	}
}

func alert(message string) {
	domain.FileLogger.Println("ALERT:", message)
}
