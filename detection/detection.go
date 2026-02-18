package detection

import (
	"fmt"
	"log"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/redis"
)

func Analyze(event domain.Event) {
	redis.StoreEvent(event)
	userRapidSuccessfulLogin(event, 8, 1*time.Minute)
	bruteforceLogin(event, 20, 1*time.Minute)
	bruteforceLogin(event, 60, 5*time.Minute)
	credentialStuffing(event, 5, 1*time.Minute)
}

func userRapidSuccessfulLogin(event domain.Event, threshold int64, window time.Duration) {
	if !event.Successful {
		return
	}

	key := "successful_login:" + event.UserID
	if err := redis.Rdb.SAdd(redis.Ctx, key, event.SourceIP).Err(); err != nil {
		log.Println("Redis SAdd error:", err)
		return
	}
	if err := redis.Rdb.Expire(redis.Ctx, key, window).Err(); err != nil {
		log.Println("Redis Expire error:", err)
	}

	count, err := redis.Rdb.SCard(redis.Ctx, key).Result()
	if err != nil {
		log.Println("Redis SCARD error:", err)
		return
	}

	if count >= threshold {
		ips, err := redis.Rdb.SMembers(redis.Ctx, key).Result()
		if err != nil {
			log.Println("Error retrieving login IPs")
			return
		}
		domain.Alert(
			fmt.Sprintf(
				"Rapid successful logins detected: %d unique IPs for user '%s' within %s — IPs: %v",
				count,
				event.UserID,
				window.String(),
				ips,
			),
		)
	}
}

func bruteforceLogin(event domain.Event, threshold int64, window time.Duration) {

	if event.Successful {
		return
	}

	key := "login:" + event.SourceIP

	count, err := redis.Rdb.Incr(redis.Ctx, key).Result()
	if err != nil {
		log.Println("Redis INCR error:", err)
		return
	}
	redis.Rdb.Expire(redis.Ctx, key, window)
	if count >= threshold {

		domain.Alert(
			fmt.Sprintf(
				"Possible bruteforce login attempts detected: %d attempts from IP %s within %s",
				count,
				event.SourceIP,
				window.String(),
			),
		)
	}
}

func credentialStuffing(event domain.Event, threshold int64, window time.Duration) {
	if event.Successful {
		return
	}

	key := "ip_targets:" + event.SourceIP

	redis.Rdb.SAdd(redis.Ctx, key, event.UserID)
	redis.Rdb.Expire(redis.Ctx, key, window)

	count, err := redis.Rdb.SCard(redis.Ctx, key).Result()
	if err != nil {
		log.Println("Redis INCR error:", err)
		return
	}
	if count >= threshold {
		domain.Alert(fmt.Sprintf(
			"Credential stuffing suspected: IP %s attempted logins against %d different users within %s",
			event.SourceIP,
			count,
			window,
		))
	}
}
