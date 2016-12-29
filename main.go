package main

import (
	"os"

	"github.com/blacktop/brobeat/beater"
	"github.com/elastic/beats/libbeat/beat"
)

func main() {
	err := beat.Run("brobeat", "", beater.New)
	if err != nil {
		os.Exit(1)
	}
}
