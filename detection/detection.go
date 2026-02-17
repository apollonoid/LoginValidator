package detection

import (
	"log"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/redis"
)

func Analyze(event domain.Event) {
	redis.StoreEvent(event)
}

func alert(message string) {
	log.Println("ALERT:", message)
}
