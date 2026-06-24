package detection

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type RuleRaw struct {
	Threshold int64  `yaml:"threshold"`
	Window    string `yaml:"window"`
}

type Rule struct {
	Threshold      int64
	WindowDuration time.Duration
}

type RuleConfig struct {
	RapidSuccessfulLogin Rule `yaml:"rapid_successful_login"`
	BruteforceLoginShort Rule `yaml:"bruteforce_login_short"`
	BruteforceLoginLong  Rule `yaml:"bruteforce_login_long"`
	CredentialStuffing   Rule `yaml:"credential_stuffing"`
}

type RedisOps interface {
	StoreEvent(domain.Event)
	AddSetMember(key, member string) (int64, error)
	SetExpiration(key string, ttl time.Duration) error
	GetSetCardinality(key string) (int64, error)
	GetSetMembers(key string) ([]string, error)
	IncrementCounter(key string) (int64, error)
}

type Processor struct {
	Cfg   RuleConfig
	Redis RedisOps
}

const (
	ruleRapidSuccessfulLogin = "rapid_successful_login"
	ruleBruteforceLoginShort = "bruteforce_login_short"
	ruleBruteforceLoginLong  = "bruteforce_login_long"
	ruleCredentialStuffing   = "credential_stuffing"
)

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

func NewProcessor(cfg RuleConfig, redisOps RedisOps) *Processor {
	return &Processor{Cfg: cfg, Redis: redisOps}
}

func (p *Processor) Analyze(event domain.Event) {
	if p == nil || p.Redis == nil {
		log.Println("detection processor is not initialized")
		return
	}

	outcome := "failure"
	if event.Successful {
		outcome = "success"
	}
	loginAttemptsTotal.WithLabelValues(event.EventType, outcome).Inc()
	log.Println("loginAttemptsTotal incremented")

	p.Redis.StoreEvent(event)
	p.userRapidSuccessfulLogin(event)
	p.bruteforceLogin(event, ruleBruteforceLoginShort, p.Cfg.BruteforceLoginShort)
	p.bruteforceLogin(event, ruleBruteforceLoginLong, p.Cfg.BruteforceLoginLong)
	p.credentialStuffing(event)
}

func (p *Processor) userRapidSuccessfulLogin(event domain.Event) {
	if !event.Successful {
		return
	}

	rule := p.Cfg.RapidSuccessfulLogin
	key := "successful_login:" + event.UserID
	if _, err := p.Redis.AddSetMember(key, event.SourceIP); err != nil {
		log.Println("Redis SAdd error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		log.Println("Redis Expire error:", err)
	}

	count, err := p.Redis.GetSetCardinality(key)
	if err != nil {
		log.Println("Redis SCARD error:", err)
		return
	}
	rapidLoginIPsHistogram.Observe(float64(count))
	log.Println("rapidLoginIPsHistogram observe")

	if count >= rule.Threshold {
		ips, err := p.Redis.GetSetMembers(key)
		if err != nil {
			log.Println("Error retrieving login IPs")
			return
		}
		domain.Alert(
			fmt.Sprintf(
				"Rapid successful logins detected: %d unique IPs for user '%s' within %s — IPs: %v",
				count,
				event.UserID,
				rule.WindowDuration.String(),
				ips,
			),
		)
		detectionsTotal.WithLabelValues(ruleRapidSuccessfulLogin).Inc()
		log.Println("detectionsTotal incremented")
	}
}

func (p *Processor) bruteforceLogin(event domain.Event, ruleName string, rule Rule) {
	if event.Successful {
		return
	}

	key := bruteForceCounterKey(ruleName, event.SourceIP)

	count, err := p.Redis.IncrementCounter(key)
	if err != nil {
		log.Println("Redis INCR error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		log.Println("Redis Expire error:", err)
	}
	bruteforceAttemptsHistogram.WithLabelValues(ruleName).Observe(float64(count))
	log.Println("bruteforceAttemptsHistogram Observe")
	if count >= rule.Threshold {
		domain.Alert(
			fmt.Sprintf(
				"Possible bruteforce login attempts detected: %d attempts from IP %s within %s",
				count,
				event.SourceIP,
				rule.WindowDuration.String(),
			),
		)
		detectionsTotal.WithLabelValues(ruleName).Inc()
		log.Println("detectionsTotal incremented")
	}
}

func bruteForceCounterKey(ruleName, sourceIP string) string {
	return ruleName + ":" + sourceIP
}

func (p *Processor) credentialStuffing(event domain.Event) {
	if event.Successful {
		return
	}

	rule := p.Cfg.CredentialStuffing
	key := "ip_targets:" + event.SourceIP

	if _, err := p.Redis.AddSetMember(key, event.UserID); err != nil {
		log.Println("Redis SAdd error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		log.Println("Redis Expire error:", err)
	}

	count, err := p.Redis.GetSetCardinality(key)
	if err != nil {
		log.Println("Redis INCR error:", err)
		return
	}
	credentialStuffingTargetsHistogram.Observe(float64(count))
	if count >= rule.Threshold {
		domain.Alert(fmt.Sprintf(
			"Credential stuffing suspected: IP %s attempted logins against %d different users within %s",
			event.SourceIP,
			count,
			rule.WindowDuration,
		))
		detectionsTotal.WithLabelValues(ruleCredentialStuffing).Inc()
		log.Println("detectionsTotal incremented")
	}
}

func StartMetricsServer(addr string) {
	metricsServerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		go func() {
			detectionsTotal.WithLabelValues(ruleRapidSuccessfulLogin).Add(0)
			detectionsTotal.WithLabelValues(ruleBruteforceLoginShort).Add(0)
			detectionsTotal.WithLabelValues(ruleBruteforceLoginLong).Add(0)
			detectionsTotal.WithLabelValues(ruleCredentialStuffing).Add(0)

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
		if dur <= 0 {
			return Rule{}, fmt.Errorf("%s window must be positive", name)
		}
		return Rule{Threshold: r.Threshold, WindowDuration: dur}, nil
	}

	cfg := RuleConfig{}
	if cfg.RapidSuccessfulLogin, err = parse(ruleRapidSuccessfulLogin, rawCfg.RapidSuccessfulLogin); err != nil {
		return nil, err
	}
	if cfg.BruteforceLoginShort, err = parse(ruleBruteforceLoginShort, rawCfg.BruteforceLoginShort); err != nil {
		return nil, err
	}
	if cfg.BruteforceLoginLong, err = parse(ruleBruteforceLoginLong, rawCfg.BruteforceLoginLong); err != nil {
		return nil, err
	}
	if cfg.CredentialStuffing, err = parse(ruleCredentialStuffing, rawCfg.CredentialStuffing); err != nil {
		return nil, err
	}
	if err := validateRuleConfig(cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateRuleConfig(cfg RuleConfig) error {
	if cfg.BruteforceLoginShort.WindowDuration > cfg.BruteforceLoginLong.WindowDuration {
		return fmt.Errorf("%s window must be less than or equal to %s window", ruleBruteforceLoginShort, ruleBruteforceLoginLong)
	}
	if cfg.BruteforceLoginShort.Threshold > cfg.BruteforceLoginLong.Threshold {
		return fmt.Errorf("%s threshold must be less than or equal to %s threshold", ruleBruteforceLoginShort, ruleBruteforceLoginLong)
	}
	return nil
}
