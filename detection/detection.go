package detection

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/apollonoid/LoginValidator/redis"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type RuleRaw struct {
	Threshold int64  `yaml:"threshold"`
	Window    string `yaml:"window"` // string from YAML
}

type Rule struct {
	Threshold      int64
	WindowDuration time.Duration // parsed
}

type RuleConfig struct {
	RapidSuccessfulLogin Rule `yaml:"rapid_successful_login"`
	BruteforceLoginShort Rule `yaml:"bruteforce_login_short"`
	BruteforceLoginLong  Rule `yaml:"bruteforce_login_long"`
	CredentialStuffing   Rule `yaml:"credential_stuffing"`
}

var cfg *RuleConfig
var metricsServerOnce sync.Once

var (
	loginAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts processed by the detection engine.",
		},
		[]string{"event_type", "outcome"},
	)

	detectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_detection_alerts_total",
			Help: "Total number of detection alerts raised by rule type.",
		},
		[]string{"rule"},
	)

	rapidLoginIPsHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "login_rapid_success_unique_ips",
			Help:    "Distribution of unique IP counts observed for rapid successful login evaluation.",
			Buckets: []float64{1, 2, 5, 10, 20, 50},
		},
	)

	bruteforceAttemptsHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "login_bruteforce_attempts",
			Help:    "Distribution of failed login attempt counts observed during brute force evaluation.",
			Buckets: []float64{1, 2, 3, 5, 10, 20, 50, 100},
		},
		[]string{"rule"},
	)

	credentialStuffingTargetsHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "login_credential_stuffing_targets",
			Help:    "Distribution of distinct targeted user counts observed during credential stuffing evaluation.",
			Buckets: []float64{1, 2, 3, 5, 10, 20, 50, 100},
		},
	)
)

func InitRules(path string) {
	var err error
	cfg, err = LoadRules(path)
	if err != nil {
		domain.Alert(fmt.Sprintf("Error loading rules: %s", err.Error()))
		log.Printf("Error loading rules: %s", err.Error())
		panic("Fatal error loading rules")
	}

	StartMetricsServer(":2112")
}

func StartMetricsServer(addr string) {
	metricsServerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		go func() {
			detectionsTotal.WithLabelValues("rapid_successful_login").Add(0)
			detectionsTotal.WithLabelValues("bruteforce_login_short").Add(0)
			detectionsTotal.WithLabelValues("bruteforce_login_long").Add(0)
			detectionsTotal.WithLabelValues("credential_stuffing").Add(0)

			log.Printf("Prometheus metrics listening on %s/metrics", addr)
			if err := http.ListenAndServe(addr, mux); err != nil {
				log.Printf("Prometheus metrics server error: %v", err)
			}
		}()
	})
}

func LoadRules(path string) (*RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawCfg struct {
		RapidSuccessfulLogin RuleRaw `yaml:"rapid_successful_login"`
		BruteforceLoginShort RuleRaw `yaml:"bruteforce_login_short"`
		BruteforceLoginLong  RuleRaw `yaml:"bruteforce_login_long"`
		CredentialStuffing   RuleRaw `yaml:"credential_stuffing"`
	}
	if err := yaml.Unmarshal(data, &rawCfg); err != nil {
		return nil, err
	}
	parse := func(name string, r RuleRaw) (Rule, error) {
		if r.Threshold <= 0 {
			return Rule{}, fmt.Errorf("%s threshold must be positive", name)
		}
		dur, err := time.ParseDuration(r.Window)
		if err != nil {
			return Rule{}, err
		}
		return Rule{Threshold: r.Threshold, WindowDuration: dur}, nil
	}

	cfg := RuleConfig{}
	if cfg.RapidSuccessfulLogin, err = parse("rapid_successful_login", rawCfg.RapidSuccessfulLogin); err != nil {
		return nil, err
	}
	if cfg.BruteforceLoginShort, err = parse("bruteforce_login_short", rawCfg.BruteforceLoginShort); err != nil {
		return nil, err
	}
	if cfg.BruteforceLoginLong, err = parse("bruteforce_login_long", rawCfg.BruteforceLoginLong); err != nil {
		return nil, err
	}
	if cfg.CredentialStuffing, err = parse("credential_stuffing", rawCfg.CredentialStuffing); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Analyze(event domain.Event) {
	outcome := "failure"
	if event.Successful {
		outcome = "success"
	}
	loginAttemptsTotal.WithLabelValues(event.EventType, outcome).Inc()
	log.Println("loginAttemptsTotal incremented")

	redis.StoreEvent(event)
	userRapidSuccessfulLogin(event, cfg.RapidSuccessfulLogin.Threshold, cfg.RapidSuccessfulLogin.WindowDuration)
	bruteforceLogin(event, cfg.BruteforceLoginLong.Threshold, cfg.BruteforceLoginLong.WindowDuration)
	bruteforceLogin(event, cfg.BruteforceLoginShort.Threshold, cfg.BruteforceLoginShort.WindowDuration)
	credentialStuffing(event, cfg.CredentialStuffing.Threshold, cfg.CredentialStuffing.WindowDuration)
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
	rapidLoginIPsHistogram.Observe(float64(count))
	log.Println("rapidLoginIPsHistogram observe")

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
		detectionsTotal.WithLabelValues("rapid_successful_login").Inc()
		log.Println("detectionsTotal incremented")
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
	ruleName := "bruteforce_login_short"
	if threshold == cfg.BruteforceLoginLong.Threshold && window == cfg.BruteforceLoginLong.WindowDuration {
		ruleName = "bruteforce_login_long"
	}
	bruteforceAttemptsHistogram.WithLabelValues(ruleName).Observe(float64(count))
	log.Println("bruteforceAttemptsHistogram Observe")
	if count >= threshold {
		domain.Alert(
			fmt.Sprintf(
				"Possible bruteforce login attempts detected: %d attempts from IP %s within %s",
				count,
				event.SourceIP,
				window.String(),
			),
		)
		detectionsTotal.WithLabelValues(ruleName).Inc()
		log.Println("detectionsTotal incremented")
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
	credentialStuffingTargetsHistogram.Observe(float64(count))
	if count >= threshold {
		domain.Alert(fmt.Sprintf(
			"Credential stuffing suspected: IP %s attempted logins against %d different users within %s",
			event.SourceIP,
			count,
			window,
		))
		detectionsTotal.WithLabelValues("credential_stuffing").Inc()
		log.Println("detectionsTotal incremented")
	}
}
