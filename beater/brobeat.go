package beater

import (
	"fmt"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/blacktop/brobeat/config"
)

// Brobeat beat struct
type Brobeat struct {
	done   chan struct{}
	config config.Config
	client publisher.Client
}

// New creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Brobeat{
		done:   make(chan struct{}),
		config: config,
	}
	return bt, nil
}

// Run start beater
func (bt *Brobeat) Run(b *beat.Beat) error {
	logp.Info("brobeat is running! Hit CTRL-C to stop it.")

	bt.client = b.Publisher.Connect()
	path := bt.config.Path
	// ticker := time.NewTicker(bt.config.Period)
	counter := 1
	// for {
	// 	select {
	// 	case <-bt.done:
	// 		return nil
	// 	case <-ticker.C:
	// 	}
	bro := ParseLogFile(path)
	for _, log := range bro.Logs {
		fmt.Println(log)
		event := common.MapStr{
			"@timestamp": common.Time(time.Now()),
			// "type":       b.Name,
			"type":    log.Type,
			"created": log.Created,
			"counter": counter,
		}
		for _, field := range log.Fields {
			// use ts field as @timestamp
			if field.Name == "ts" {
				time, err := convertTs2Time(field.Value)
				if err != nil {
					return err
				}
				fmt.Println(time)
				event["@timestamp"] = common.Time(time)
			}
			// don't output fields with '-' values
			if field.Value != log.UnsetField {
				event[field.Name] = field.Value
			}
		}

		bt.client.PublishEvent(event)
		logp.Info("Event sent")
		counter++
	}

	// }
	return nil
}

// Stop stops beater
func (bt *Brobeat) Stop() {
	bt.client.Close()
	close(bt.done)
}
