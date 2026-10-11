package main

import (
	"encoding/json"

	"github.com/BishopFox/jsluice"
)

// extractPostMessage prints one JSON object per line for each place that
// the JavaScript receives or sends a cross-origin message with postMessage.
func extractPostMessage(opts options, filename string, source []byte, output chan string, errs chan error) {
	analyzer := jsluice.NewAnalyzer(source)

	for _, l := range analyzer.GetMessageListeners() {
		l.Filename = filename

		j, err := json.Marshal(l)
		if err != nil {
			errs <- err
			continue
		}
		output <- string(j)
	}
}
