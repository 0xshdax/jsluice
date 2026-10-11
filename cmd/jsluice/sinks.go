package main

import (
	"encoding/json"

	"github.com/BishopFox/jsluice"
)

// extractSinks finds DOM-XSS sinks (innerHTML, document.write, eval etc)
// in the input and outputs one JSON object per sink.
func extractSinks(opts options, filename string, source []byte, output chan string, errs chan error) {
	analyzer := jsluice.NewAnalyzer(source)

	for _, sink := range analyzer.GetSinks() {
		sink.Filename = filename

		j, err := json.Marshal(sink)
		if err != nil {
			errs <- err
			continue
		}
		output <- string(j)
	}
}
