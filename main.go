package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"

	"github.com/blacktop/brobeat/beater"
)

func main() {
	err := beat.Run("brobeat", "", beater.New)
	if err != nil {
		os.Exit(1)
	}
}
