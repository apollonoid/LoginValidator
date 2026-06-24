package pipeline

import (
	"runtime"

	"github.com/apollonoid/LoginValidator/domain"
)

type IngestionChannel chan domain.Event
type Analyzer func(domain.Event)

var EventsChannel IngestionChannel

func InitPipeline(analyze Analyzer) {
	if analyze == nil {
		panic("pipeline analyzer must not be nil")
	}

	EventsChannel = make(IngestionChannel, 1000)
	workersNumber := runtime.NumCPU()
	for i := range workersNumber {
		go func(id int) {
			for event := range EventsChannel {
				analyze(event)
			}
		}(i)
	}
}
