package pipeline

import (
	"runtime"

	"github.com/apollonoid/LoginValidator/detection"
	"github.com/apollonoid/LoginValidator/domain"
)

type IngestionChannel chan domain.Event

var EventsChannel IngestionChannel

func InitPipeline() {
	EventsChannel = make(IngestionChannel, 1000)
	workersNumber := runtime.NumCPU()
	for i := range workersNumber {
		go func(id int) {
			for event := range EventsChannel {
				detection.Analyze(event)
			}
		}(i)
	}
}
