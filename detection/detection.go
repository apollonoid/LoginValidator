package detection

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/redis"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	Threshold int64         `yaml:"threshold"`
	Window    time.Duration `yaml:"window"`
}

type RuleConfig struct {
	RapidSuccessfulLogin Rule `yaml:"rapid_successful_login"`
	BruteforceLoginShort Rule `yaml:"bruteforce_login_short"`
	BruteforceLoginLong  Rule `yaml:"bruteforce_login_long"`
	CredentialStuffing   Rule `yaml:"credential_stuffing"`
}

func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	type RawRule struct {
		Threshold int64  `yaml:"threshold"`
		Window    string `yaml:"window"`
	}

	var tmp RawRule
	err := value.Decode(&tmp)
	if err != nil {
		return err
	}
	r.Threshold = tmp.Threshold
	window, err := time.ParseDuration(tmp.Window)
	if err != nil {
		return err
	}
	r.Window = window
	return nil
}

var cfg *RuleConfig

func InitRules(path string) {
	var err error
	cfg, err = LoadRules(path)
	if err != nil {
		domain.Alert(fmt.Sprintf("Error loading rules: %v", err))
		panic("Fatal error loading rules")
	}
}

func LoadRules(path string) (*RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rulesCfg := RuleConfig{}
	err = yaml.Unmarshal(data, &rulesCfg)
	if err != nil {
		return nil, err
	}
	return &rulesCfg, nil
}

func Analyze(event domain.Event) {
	redis.StoreEvent(event)
	userRapidSuccessfulLogin(event, cfg.RapidSuccessfulLogin.Threshold, cfg.RapidSuccessfulLogin.Window)
	bruteforceLogin(event, cfg.BruteforceLoginLong.Threshold, cfg.BruteforceLoginLong.Window)
	bruteforceLogin(event, cfg.BruteforceLoginShort.Threshold, cfg.BruteforceLoginShort.Window)
	credentialStuffing(event, cfg.CredentialStuffing.Threshold, cfg.CredentialStuffing.Window)
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
