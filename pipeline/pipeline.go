package pipeline

import (
	"runtime"

	"github.com/apollonoid/LoginValidator/domain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type IngestionChannel chan domain.Event
type Analyzer func(domain.Event)

var EventsChannel IngestionChannel

var queueDepth = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "login_pipeline_queue_depth",
		Help: "Current number of events waiting in the ingestion pipeline.",
	},
)

func InitPipeline(analyze Analyzer) {
	if analyze == nil {
		panic("pipeline analyzer must not be nil")
	}

	EventsChannel = make(IngestionChannel, 1000)
	UpdateQueueDepth()
	workersNumber := runtime.NumCPU()
	for i := range workersNumber {
		go func(id int) {
			for event := range EventsChannel {
				UpdateQueueDepth()
				analyze(event)
			}
		}(i)
	}
}

func UpdateQueueDepth() {
	if EventsChannel == nil {
		queueDepth.Set(0)
		return
	}
	queueDepth.Set(float64(len(EventsChannel)))
}
