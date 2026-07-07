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
var alertActiveResetters = make(map[string]*time.Timer)
var alertActiveMu sync.Mutex
var alertSuppressionTimers = make(map[string]*time.Timer)
var alertSuppressionMu sync.Mutex

const alertActiveHoldDuration = 15 * time.Second

var (
	loginEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_events_total",
			Help: "Total number of login events processed by the detection engine.",
		},
		[]string{"outcome"},
	)

	detectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_detection_alerts_total",
			Help: "Total number of alert firings raised by rule type.",
		},
		[]string{"rule"},
	)

	alertActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "login_detection_alert_active",
			Help: "Current alert state by rule. Set to 1 when an alert fires and reset to 0 after a short hold period.",
		},
		[]string{"rule"},
	)

	processingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "login_processing_duration_seconds",
			Help:    "Distribution of processor execution times in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
	)

	systemErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_system_errors_total",
			Help: "Total number of internal system errors observed while processing events.",
		},
		[]string{"component", "operation"},
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
	start := time.Now()
	defer func() {
		processingDuration.Observe(time.Since(start).Seconds())
	}()

	outcome := "failure"
	if event.Successful {
		outcome = "success"
	}
	loginEventsTotal.WithLabelValues(outcome).Inc()

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
		p.recordSystemError("redis", "sadd")
		log.Println("Redis SAdd error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		p.recordSystemError("redis", "expire")
		log.Println("Redis Expire error:", err)
	}

	count, err := p.Redis.GetSetCardinality(key)
	if err != nil {
		p.recordSystemError("redis", "scard")
		log.Println("Redis SCARD error:", err)
		return
	}

	if count >= rule.Threshold {
		ips, err := p.Redis.GetSetMembers(key)
		if err != nil {
			p.recordSystemError("redis", "smembers")
			log.Println("Error retrieving login IPs")
			return
		}
		if !shouldFireAlert(alertCooldownKey(ruleRapidSuccessfulLogin, event.UserID), rule.WindowDuration) {
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
		pulseAlertActive(ruleRapidSuccessfulLogin)
	}
}

func (p *Processor) bruteforceLogin(event domain.Event, ruleName string, rule Rule) {
	if event.Successful {
		return
	}

	key := bruteForceCounterKey(ruleName, event.SourceIP)

	count, err := p.Redis.IncrementCounter(key)
	if err != nil {
		p.recordSystemError("redis", "incr")
		log.Println("Redis INCR error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		p.recordSystemError("redis", "expire")
		log.Println("Redis Expire error:", err)
	}
	if count >= rule.Threshold {
		if !shouldFireAlert(alertCooldownKey(ruleName, event.SourceIP), rule.WindowDuration) {
			return
		}
		domain.Alert(
			fmt.Sprintf(
				"Possible bruteforce login attempts detected: %d attempts from IP %s within %s",
				count,
				event.SourceIP,
				rule.WindowDuration.String(),
			),
		)
		detectionsTotal.WithLabelValues(ruleName).Inc()
		pulseAlertActive(ruleName)
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
		p.recordSystemError("redis", "sadd")
		log.Println("Redis SAdd error:", err)
		return
	}
	if err := p.Redis.SetExpiration(key, rule.WindowDuration); err != nil {
		p.recordSystemError("redis", "expire")
		log.Println("Redis Expire error:", err)
	}

	count, err := p.Redis.GetSetCardinality(key)
	if err != nil {
		p.recordSystemError("redis", "scard")
		log.Println("Redis INCR error:", err)
		return
	}
	if count >= rule.Threshold {
		if !shouldFireAlert(alertCooldownKey(ruleCredentialStuffing, event.SourceIP), rule.WindowDuration) {
			return
		}
		domain.Alert(fmt.Sprintf(
			"Credential stuffing suspected: IP %s attempted logins against %d different users within %s",
			event.SourceIP,
			count,
			rule.WindowDuration,
		))
		detectionsTotal.WithLabelValues(ruleCredentialStuffing).Inc()
		pulseAlertActive(ruleCredentialStuffing)
	}
}

func pulseAlertActive(rule string) {
	alertActive.WithLabelValues(rule).Set(1)

	alertActiveMu.Lock()
	defer alertActiveMu.Unlock()

	if timer, ok := alertActiveResetters[rule]; ok {
		timer.Stop()
	}
	alertActiveResetters[rule] = time.AfterFunc(alertActiveHoldDuration, func() {
		alertActive.WithLabelValues(rule).Set(0)
	})
}

func alertCooldownKey(ruleName, subject string) string {
	return ruleName + ":" + subject
}

func shouldFireAlert(key string, hold time.Duration) bool {
	alertSuppressionMu.Lock()
	defer alertSuppressionMu.Unlock()

	if _, ok := alertSuppressionTimers[key]; ok {
		return false
	}

	alertSuppressionTimers[key] = time.AfterFunc(hold, func() {
		alertSuppressionMu.Lock()
		delete(alertSuppressionTimers, key)
		alertSuppressionMu.Unlock()
	})
	return true
}

func (p *Processor) recordSystemError(component, operation string) {
	systemErrorsTotal.WithLabelValues(component, operation).Inc()
}

func StartMetricsServer(addr string) {
	metricsServerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		go func() {
			loginEventsTotal.WithLabelValues("success").Add(0)
			loginEventsTotal.WithLabelValues("failure").Add(0)
			detectionsTotal.WithLabelValues(ruleRapidSuccessfulLogin).Add(0)
			detectionsTotal.WithLabelValues(ruleBruteforceLoginShort).Add(0)
			detectionsTotal.WithLabelValues(ruleBruteforceLoginLong).Add(0)
			detectionsTotal.WithLabelValues(ruleCredentialStuffing).Add(0)
			alertActive.WithLabelValues(ruleRapidSuccessfulLogin).Add(0)
			alertActive.WithLabelValues(ruleBruteforceLoginShort).Add(0)
			alertActive.WithLabelValues(ruleBruteforceLoginLong).Add(0)
			alertActive.WithLabelValues(ruleCredentialStuffing).Add(0)
			systemErrorsTotal.WithLabelValues("redis", "sadd").Add(0)
			systemErrorsTotal.WithLabelValues("redis", "expire").Add(0)
			systemErrorsTotal.WithLabelValues("redis", "scard").Add(0)
			systemErrorsTotal.WithLabelValues("redis", "smembers").Add(0)
			systemErrorsTotal.WithLabelValues("redis", "incr").Add(0)

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
