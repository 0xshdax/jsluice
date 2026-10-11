package jsluice

import (
	"bytes"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// smMaxSource is the maximum number of bytes of comment text that
// is kept in the Source field of a result.
const smMaxSource = 300

// smNewline is used to count lines.
var smNewline = []byte{'\n'}

// A SourceMap is a reference to a source map, or to a source URL, that
// was found in a "magic comment" such as:
//
//	//# sourceMappingURL=app.js.map
//	//# sourceURL=webpack:///./src/app.js
//
// Fetching the referenced .map file usually yields the original,
// un-minified source code for a bundle.
type SourceMap struct {
	// Kind is the type of magic comment: "sourceMappingURL" or "sourceURL"
	Kind string `json:"kind"`

	// URL is the external reference, exactly as it appears in the comment
	// (i.e. relative references are not resolved). It is empty for inline
	// source maps.
	URL string `json:"url,omitempty"`

	// Inline is true when the source map is embedded in the comment
	// as a data: URI instead of being referenced by URL.
	Inline bool `json:"inline"`

	// Line is the line number (starting at 1) of the JavaScript that
	// was analyzed on which the reference was found. For HTML input that
	// is the extracted inline JavaScript, not the HTML.
	Line int `json:"line"`

	// Source is the text of the comment containing the reference
	// (truncated to roughly 300 characters).
	Source string `json:"source"`

	// the filename in which the match was found
	Filename string `json:"filename,omitempty"`
}

// GetSourceMaps searches the JavaScript source for source map references;
// i.e. "magic comments" like:
//
//	//# sourceMappingURL=app.js.map
//	//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjoz...
//	/*# sourceMappingURL=style.css.map */
//	//# sourceURL=webpack:///./src/app.js
//
// The match is case-insensitive. Comments are found using the syntax tree,
// but as minified bundles often have the comment on their very last line
// (and bundlers embed these comments in strings too, e.g. in eval()'d
// modules) the raw source is scanned as well and the results are merged.
// References are de-duplicated on kind, URL, and line; results are returned
// in the order they appear in the source.
func (a *Analyzer) GetSourceMaps() []*SourceMap {
	out := make([]*SourceMap, 0)
	if a == nil || a.rootNode == nil {
		return out
	}

	hits := make([]smHit, 0)

	// Comments that tree-sitter knows about. These go first so that, when the
	// raw scan finds the same thing, it is the result with the complete comment
	// text as its Source that is kept.
	a.rootNode.Query("(comment) @c", func(n *Node) {
		text := []byte(n.Content())
		base := int(n.node.StartByte())
		row := int(n.node.StartPoint().Row)

		snippet := ""
		for _, d := range smScan(text, false) {
			if snippet == "" {
				snippet = smSnippet(text)
			}

			// block comments can span many lines, so the line the
			// reference is on isn't necessarily the one the comment starts on
			line := row + 1 + bytes.Count(text[:d.start], smNewline)

			hits = append(hits, smHit{sm: d.sourceMap(snippet, line), offset: base + d.start})
		}
	})

	hits = append(hits, smRawScan(a.rootNode.source)...)

	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].offset < hits[j].offset
	})

	seen := make(set)
	for _, h := range hits {
		key := h.key()
		if seen.Contains(key) {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h.sm)
	}

	return out
}

// GetCommentURLs searches the comments in the JavaScript source for URLs
// and paths that developers have left behind; e.g:
//
//	// TODO: remove /internal/admin before launch
//	/* docs: https://api.example.com/v2/docs */
//	// fetch("/api/v1/debug")
//
// Comment text is split into tokens on whitespace and quotes, and every
// token that MaybeURL considers to be a URL is returned with the type
// "comment". Each URL is returned once, in order of appearance. Source map
// references are not included here; see GetSourceMaps for those.
func (a *Analyzer) GetCommentURLs() []*URL {
	out := make([]*URL, 0)
	if a == nil || a.rootNode == nil {
		return out
	}

	seen := make(set)

	a.rootNode.Query("(comment) @c", func(n *Node) {
		comment := n.Content()

		// Magic comments are handled by GetSourceMaps. Blank them out
		// so that we don't get junk like 'sourceURL=app.js' as a URL.
		text := []byte(comment)
		for _, d := range smScan(text, false) {
			for i := d.start; i < d.end; i++ {
				text[i] = ' '
			}
		}

		snippet := ""
		for _, token := range smCommentTokens(string(text)) {
			if seen.Contains(token) {
				continue
			}

			u := smCommentURL(token)
			if u == nil {
				continue
			}
			seen[token] = struct{}{}

			if snippet == "" {
				snippet = smSnippet([]byte(comment))
			}
			u.Source = snippet

			out = append(out, u)
		}
	})

	return out
}

// smHit is a SourceMap along with the offset in the analyzed source at
// which it was found. The offset is used for ordering and de-duplication.
type smHit struct {
	sm     *SourceMap
	offset int
}

// key returns the key that hits are de-duplicated on. Hits are considered
// to be the same when the kind, URL and line match. Inline source maps
// have no URL, so the offset is used for them instead to avoid collapsing
// two different maps that just happen to be on the same line.
func (h smHit) key() string {
	if h.sm.Inline {
		return h.sm.Kind + "\x00inline\x00" + strconv.Itoa(h.sm.Line) + "\x00" + strconv.Itoa(h.offset)
	}
	return h.sm.Kind + "\x00" + h.sm.URL + "\x00" + strconv.Itoa(h.sm.Line)
}

// smDirective is a magic comment found in some text.
type smDirective struct {
	kind   string // sourceMappingURL or sourceURL
	value  string // the reference; empty for an inline source map
	inline bool
	start  int // offset of the start of the directive, including any comment opener
	end    int // offset of the end of the reference
}

// sourceMap converts the directive to a *SourceMap
func (d smDirective) sourceMap(source string, line int) *SourceMap {
	return &SourceMap{
		Kind:   d.kind,
		URL:    d.value,
		Inline: d.inline,
		Line:   line,
		Source: source,
	}
}

// smNames are the names of the magic comments we look for. The lowercase
// form is what we search for, the other is what ends up in the Kind field.
var smNames = []struct {
	lower string
	kind  string
}{
	{"sourcemappingurl", "sourceMappingURL"},
	{"sourceurl", "sourceURL"},
}

// smRawScan scans raw source code, ignoring the syntax tree, for source map
// references. It is the fallback for when the tree-sitter parse doesn't
// give us a comment node (e.g. the reference is inside a string, or the
// parser got confused by something earlier in a minified file).
//
// Because the whole of a source file is scanned, rather than just the text
// of a comment, it is stricter than the matching done on comments: the
// reference has to be immediately preceded by a comment opener (// or /*).
// That keeps code that deals with source maps (regular expressions that parse
// them, strings that build them, etc.) from showing up as source maps.
func smRawScan(source []byte) []smHit {
	hits := make([]smHit, 0)

	// directives are sorted by their position, so we can
	// count lines as we go instead of starting again every time
	line, last := 1, 0
	for _, d := range smScan(source, true) {
		line += bytes.Count(source[last:d.start], smNewline)
		last = d.start

		hits = append(hits, smHit{
			sm:     d.sourceMap(smSnippet(source[d.start:d.end]), line),
			offset: d.start,
		})
	}

	return hits
}

// smScan finds magic comments in text, sorted by their position.
//
// What it matches is essentially:
//
//	[#@]\s*sourceMappingURL\s*=\s*(\S+)
//	[#@]\s*sourceURL\s*=\s*(\S+)
//
// case-insensitively, with some refinements:
//
//   - Only spaces and tabs are allowed around the name and the equals sign, as
//     a comment can't carry on to the next line.
//   - The value ends at whitespace, a quote, a backtick, a backslash, or the
//     end of a block comment. Bundlers embed these comments in strings, where
//     they're followed by a quote or an escaped newline (\n).
//   - Empty values, and values that are obviously placeholders, are ignored.
//
// Rather than running a regular expression over what can be a multi-megabyte
// bundle, the text is searched for the names and the surroundings of each
// are inspected.
//
// If requireOpener is true then the directive must be immediately preceded
// by a comment opener (// or /*).
func smScan(text []byte, requireOpener bool) []smDirective {
	var out []smDirective
	if len(text) < len("sourceurl") {
		return out
	}

	folded := smFold(text)

	for _, name := range smNames {
		needle := []byte(name.lower)

		for from := 0; from < len(folded); {
			i := bytes.Index(folded[from:], needle)
			if i < 0 {
				break
			}
			pos := from + i
			from = pos + len(needle)

			d, ok := smParse(text, pos, len(needle), name.kind, requireOpener)
			if !ok {
				continue
			}
			out = append(out, d)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].start < out[j].start
	})

	return out
}

// smParse inspects the text around a name (sourceMappingURL etc) found at
// position pos in text, and returns the magic comment it is part of; if any.
func smParse(text []byte, pos, length int, kind string, requireOpener bool) (smDirective, bool) {
	none := smDirective{}

	// the name must be preceded by a # or @
	i := pos
	for i > 0 && smBlank(text[i-1]) {
		i--
	}
	if i == 0 || (text[i-1] != '#' && text[i-1] != '@') {
		return none, false
	}
	start := i - 1

	// and that is usually preceded by a comment opener
	k := start
	for k > 0 && smBlank(text[k-1]) {
		k--
	}
	if k >= 2 && text[k-2] == '/' && (text[k-1] == '/' || text[k-1] == '*') {
		start = k - 2
	} else if requireOpener {
		return none, false
	}

	// then it's followed by an equals sign and the value
	j := pos + length
	for j < len(text) && smBlank(text[j]) {
		j++
	}
	if j >= len(text) || text[j] != '=' {
		return none, false
	}
	j++
	for j < len(text) && smBlank(text[j]) {
		j++
	}

	valueStart := j
	for j < len(text) {
		c := text[j]

		if c == '*' && j+1 < len(text) && text[j+1] == '/' {
			break
		}

		if c < utf8.RuneSelf {
			if smValueEnd(c) {
				break
			}
			j++
			continue
		}

		r, size := utf8.DecodeRune(text[j:])
		if unicode.IsSpace(r) {
			break
		}
		j += size
	}

	value := text[valueStart:j]
	if len(value) == 0 {
		return none, false
	}

	d := smDirective{kind: kind, start: start, end: j}

	// inline source maps; we don't keep the (often huge) data
	if kind == "sourceMappingURL" && len(value) >= len("data:") && bytes.EqualFold(value[:len("data:")], []byte("data:")) {
		// strings that build comments look like data:application/json;base64,
		// with nothing after the comma, and those aren't source maps.
		comma := bytes.IndexByte(value, ',')
		if comma < 0 || comma == len(value)-1 {
			return none, false
		}
		d.inline = true
		return d, true
	}

	d.value = string(value)
	if !smPlausible(d.value) {
		return none, false
	}

	return d, true
}

// smBlank returns true for the whitespace allowed inside a magic comment
func smBlank(c byte) bool {
	return c == ' ' || c == '\t'
}

// smValueEnd returns true for the (ASCII) characters that end the value in a magic comment
func smValueEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', '"', '\'', '`', '\\':
		return true
	}
	return false
}

// smPlausible returns false for values that are obviously
// not real references, like '<url>' or '${url}'.
func smPlausible(value string) bool {
	if strings.ContainsAny(value, "<>") ||
		strings.Contains(value, "${") ||
		strings.Contains(value, "{{") {
		return false
	}
	return smHasAlnum(value)
}

// smHasAlnum returns true if the string contains at least one letter or digit
func smHasAlnum(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	}) >= 0
}

// smFold returns a copy of b with ASCII letters lowercased. Unlike
// bytes.ToLower the result is always the same length as the input, so
// offsets in the result are valid for the original too.
func smFold(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// smSnippet returns b as a string, cut down to roughly smMaxSource bytes
// (without splitting a UTF-8 sequence) if it is longer than that.
func smSnippet(b []byte) string {
	if len(b) <= smMaxSource {
		return string(b)
	}

	cut := smMaxSource
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}

	return string(b[:cut]) + "..."
}

const (
	// Punctuation that tends to surround URLs in comments, but that isn't a
	// part of them. Quotes aren't in here because they separate tokens.
	smTrimLeft  = "([{<"
	smTrimRight = ".,;:!)]}>"
)

// smCommentTokens splits the text of a comment up and returns the tokens
// that are URLs, according to MaybeURL.
//
// Tokens are separated by whitespace and quotes. The quotes mean that
// URLs in commented out code are found, e.g:
//
//	// $.post('/admin/delete', {id: id})
//
// Splitting on parentheses and the like as well would find even more,
// but those aren't safe: 'res.json()' would turn into the URL 'res.json'.
func smCommentTokens(comment string) []string {
	switch {
	case strings.HasPrefix(comment, "/*"):
		comment = strings.TrimSuffix(strings.TrimPrefix(comment, "/*"), "*/")
	case strings.HasPrefix(comment, "//"):
		comment = comment[2:]
	}

	fields := strings.FieldsFunc(comment, func(r rune) bool {
		return unicode.IsSpace(r) || r == '"' || r == '\'' || r == '`'
	})

	out := make([]string, 0)
	for _, token := range fields {
		token = strings.TrimRight(strings.TrimLeft(token, smTrimLeft), smTrimRight)
		token = smKeyValue(token)
		token = strings.TrimRight(strings.TrimLeft(token, smTrimLeft), smTrimRight)

		// MaybeURL considers things like '/', '//' and '/*' to be paths
		if !smHasAlnum(token) || !MaybeURL(token) {
			continue
		}

		out = append(out, token)
	}

	return out
}

// smKeyValue returns the value part of tokens that look like
// key=value, e.g. 'href=/login' or 'API_URL=https://api.example.com'.
// Tokens where the key isn't a plain name are returned as they are; that
// includes URLs with query strings, like '/search?q=1'.
func smKeyValue(token string) string {
	eq := strings.IndexByte(token, '=')
	if eq <= 0 || eq == len(token)-1 {
		return token
	}

	for _, r := range token[:eq] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return token
		}
	}

	return token[eq+1:]
}

// smCommentURL returns the *URL for a token found in a comment, or
// nil if it's one of the URLs that are never interesting.
func smCommentURL(token string) *URL {
	u := &URL{
		URL:         token,
		QueryParams: []string{},
		BodyParams:  []string{},
		Type:        "comment",
	}

	parsed, err := url.Parse(token)
	if err != nil {
		return u
	}

	// the same as GetURLs; this shows up all the time
	if parsed.Hostname() == "www.w3.org" {
		return nil
	}

	for param := range parsed.Query() {
		u.QueryParams = append(u.QueryParams, param)
	}
	sort.Strings(u.QueryParams)

	return u
}
