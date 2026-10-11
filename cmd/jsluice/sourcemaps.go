package main

import (
	"encoding/json"
	"net/url"

	"github.com/BishopFox/jsluice"
)

// extractSourceMaps outputs the source map references (sourceMappingURL and
// sourceURL comments) and the URLs found in comments for a file, as one JSON
// object per line. Source maps come first, then comment URLs; the latter have
// the type 'comment'.
//
// If --resolve-paths is used then relative sourceMappingURL references and
// comment URLs are resolved against it, as they are in the urls mode.
func extractSourceMaps(opts options, filename string, source []byte, output chan string, errs chan error) {
	var resolveURL *url.URL
	if opts.resolvePaths != "" {
		var err error
		resolveURL, err = url.Parse(opts.resolvePaths)
		if err != nil {
			errs <- err
			return
		}
	}

	resolve := func(ref string) string {
		if resolveURL == nil {
			return ref
		}

		parsed, err := url.Parse(ref)
		if err != nil {
			return ref
		}
		return resolveURL.ResolveReference(parsed).String()
	}

	analyzer := jsluice.NewAnalyzer(source)

	for _, m := range analyzer.GetSourceMaps() {
		m.Filename = filename

		// a sourceURL is a name for a piece of code, rather than somewhere to fetch
		if m.Kind == "sourceMappingURL" && m.URL != "" {
			m.URL = resolve(m.URL)
		}

		j, err := json.Marshal(m)
		if err != nil {
			errs <- err
			continue
		}
		output <- string(j)
	}

	for _, u := range analyzer.GetCommentURLs() {
		u.Filename = filename
		u.URL = resolve(u.URL)

		j, err := json.Marshal(u)
		if err != nil {
			errs <- err
			continue
		}
		output <- string(j)
	}
}
