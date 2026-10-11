package jsluice

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// smSummary is the part of a SourceMap that most of the tests care about
type smSummary struct {
	Kind   string
	URL    string
	Inline bool
	Line   int
}

func smSummarize(maps []*SourceMap) []smSummary {
	out := make([]smSummary, 0, len(maps))
	for _, m := range maps {
		out = append(out, smSummary{m.Kind, m.URL, m.Inline, m.Line})
	}
	return out
}

func TestGetSourceMaps(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expected []smSummary
	}{
		{
			"external map",
			"//# sourceMappingURL=app.js.map\nvar x=1;",
			[]smSummary{{"sourceMappingURL", "app.js.map", false, 1}},
		},
		{
			"inline map using the old @ syntax",
			"//@ sourceMappingURL=data:application/json;base64,AAAA",
			[]smSummary{{"sourceMappingURL", "", true, 1}},
		},
		{
			"trailing comment on the last line with no newline",
			"var x=1;\n//# sourceMappingURL=/static/js/main.abc.js.map",
			[]smSummary{{"sourceMappingURL", "/static/js/main.abc.js.map", false, 2}},
		},
		{
			"trailing comment on the same line as code",
			"var a=1;//# sourceMappingURL=a.js.map",
			[]smSummary{{"sourceMappingURL", "a.js.map", false, 1}},
		},
		{
			"absolute URL",
			"var a=1;\n//# sourceMappingURL=https://cdn.example.com/js/app.min.js.map\n",
			[]smSummary{{"sourceMappingURL", "https://cdn.example.com/js/app.min.js.map", false, 2}},
		},
		{
			"inline map with a charset",
			"//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozfQ==",
			[]smSummary{{"sourceMappingURL", "", true, 1}},
		},
		{
			"data: scheme is case-insensitive",
			"//# sourceMappingURL=DATA:application/json;base64,AAAA",
			[]smSummary{{"sourceMappingURL", "", true, 1}},
		},
		{
			"sourceURL",
			"//# sourceURL=webpack:///./src/app.js\nvar x=1;",
			[]smSummary{{"sourceURL", "webpack:///./src/app.js", false, 1}},
		},
		{
			"sourceURL with parentheses, as seen with Next.js",
			"//# sourceURL=webpack-internal:///(app-pages-browser)/./app/page.tsx\n",
			[]smSummary{{"sourceURL", "webpack-internal:///(app-pages-browser)/./app/page.tsx", false, 1}},
		},
		{
			"sourceURL and sourceMappingURL",
			"//# sourceURL=webpack:///./src/app.js\nvar x=1;\n//# sourceMappingURL=app.js.map\n",
			[]smSummary{
				{"sourceURL", "webpack:///./src/app.js", false, 1},
				{"sourceMappingURL", "app.js.map", false, 3},
			},
		},
		{
			"case-insensitive, with the kind normalized",
			"//# SOURCEMAPPINGURL=A.map\n//# sourceurl=B.js\n",
			[]smSummary{
				{"sourceMappingURL", "A.map", false, 1},
				{"sourceURL", "B.js", false, 2},
			},
		},
		{
			"whitespace around the equals sign",
			"//#   sourceMappingURL  =   app.js.map  \n",
			[]smSummary{{"sourceMappingURL", "app.js.map", false, 1}},
		},
		{
			"block comment",
			"var a=1;\n/*# sourceMappingURL=style.css.map */",
			[]smSummary{{"sourceMappingURL", "style.css.map", false, 2}},
		},
		{
			"block comment with nothing between the URL and the end of the comment",
			"var a=1;\n/*# sourceMappingURL=style.css.map*/var b=2;",
			[]smSummary{{"sourceMappingURL", "style.css.map", false, 2}},
		},
		{
			"two block comments on one line",
			"/*# sourceURL=a.js */ /*# sourceMappingURL=a.map */",
			[]smSummary{
				{"sourceURL", "a.js", false, 1},
				{"sourceMappingURL", "a.map", false, 1},
			},
		},
		{
			"windows line endings",
			"//# sourceMappingURL=app.js.map\r\nvar x=1;\r\n",
			[]smSummary{{"sourceMappingURL", "app.js.map", false, 1}},
		},
		{
			"concatenated files",
			"var a=1;\n//# sourceMappingURL=a.js.map\nvar b=2;\n//# sourceMappingURL=b.js.map",
			[]smSummary{
				{"sourceMappingURL", "a.js.map", false, 2},
				{"sourceMappingURL", "b.js.map", false, 4},
			},
		},
		{
			"comment in a nested scope",
			"function f() {\n  return {\n    //# sourceMappingURL=nested.map\n  };\n}\n",
			[]smSummary{{"sourceMappingURL", "nested.map", false, 3}},
		},
		{
			"directive on a later line of a block comment",
			"/*\n * header\n *# sourceMappingURL=x.map\n */\nvar x=1;",
			[]smSummary{{"sourceMappingURL", "x.map", false, 3}},
		},
		{
			"same reference twice on one line is reported once",
			"/*# sourceMappingURL=a.map */ /*# sourceMappingURL=a.map */",
			[]smSummary{{"sourceMappingURL", "a.map", false, 1}},
		},

		// the raw scan finds these; tree-sitter sees strings and not comments
		{
			"sourceURL in an eval()'d string",
			`eval("var x=1;\n//# sourceURL=webpack:///./src/index.js?");`,
			[]smSummary{{"sourceURL", "webpack:///./src/index.js?", false, 1}},
		},
		{
			"inline map followed by a sourceURL in an eval()'d string",
			`eval("var x=1;\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozfQ==\n//# sourceURL=webpack-internal:///./src/a.js\n");`,
			[]smSummary{
				{"sourceMappingURL", "", true, 1},
				{"sourceURL", "webpack-internal:///./src/a.js", false, 1},
			},
		},
		{
			"inline map in a block comment in a string, as produced by css-loader",
			`module.exports = "body{color:red}\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ== */";`,
			[]smSummary{{"sourceMappingURL", "", true, 1}},
		},
		{
			"one eval()'d module per line",
			"eval(\"a\\n//# sourceURL=webpack:///./a.js\\n\");\neval(\"b\\n//# sourceURL=webpack:///./b.js\\n\");\n",
			[]smSummary{
				{"sourceURL", "webpack:///./a.js", false, 1},
				{"sourceURL", "webpack:///./b.js", false, 2},
			},
		},
		{
			"two different inline maps on the same line are both kept",
			`eval("a\n//# sourceMappingURL=data:application/json;base64,AAAA\n"); eval("b\n//# sourceMappingURL=data:application/json;base64,BBBB\n");`,
			[]smSummary{
				{"sourceMappingURL", "", true, 1},
				{"sourceMappingURL", "", true, 1},
			},
		},

		// things that look a bit like source map comments, but aren't
		{"nothing in the source", `var x = "no map here";`, []smSummary{}},
		{"empty source", ``, []smSummary{}},
		{"no # or @", "// sourceMappingURL=app.js.map\n", []smSummary{}},
		{"not a comment", `var sourceMappingURL = "app.js.map";`, []smSummary{}},
		{"empty value", "//# sourceMappingURL=\nvar x=1;", []smSummary{}},
		{"no value", "//# sourceMappingURL", []smSummary{}},
		{"value is on the next line", "//# sourceMappingURL=\napp.js.map\n", []smSummary{}},
		{"longer name", "//# sourceMappingURLs=app.js.map\n", []smSummary{}},
		{"placeholder in a comment", "// point it at your map with //# sourceMappingURL=<url> instead\n", []smSummary{}},
		{"string being concatenated", `var c = "//# sourceMappingURL=" + url;`, []smSummary{}},
		{"template string with a placeholder", "var c = `//# sourceMappingURL=${url}`;", []smSummary{}},
		{"inline map with no data", `var p = "//# sourceMappingURL=data:application/json;base64," + b64;`, []smSummary{}},
		{"regular expression", `var re = /\/\/# sourceMappingURL=(.*)$/;`, []smSummary{}},
		{"URL fragment", `var u = "http://example.com/page#sourceURL=a.js";`, []smSummary{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			maps := NewAnalyzer([]byte(c.source)).GetSourceMaps()

			actual := smSummarize(maps)
			if !reflect.DeepEqual(actual, c.expected) {
				t.Errorf("want %+v for GetSourceMaps(%q); have %+v", c.expected, c.source, actual)
			}
		})
	}
}

func TestGetSourceMapsSource(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expected string
	}{
		{
			"line comment",
			"var x=1;\n//# sourceMappingURL=app.js.map\n",
			"//# sourceMappingURL=app.js.map",
		},
		{
			"block comment, for which the whole comment is kept",
			"/*# sourceMappingURL=style.css.map */",
			"/*# sourceMappingURL=style.css.map */",
		},
		{
			"embedded in a string, for which the comment is all we have",
			`eval("x\n//# sourceURL=webpack:///./src/index.js?");`,
			"//# sourceURL=webpack:///./src/index.js?",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			maps := NewAnalyzer([]byte(c.source)).GetSourceMaps()
			if len(maps) != 1 {
				t.Fatalf("want 1 source map for %q; have %d", c.source, len(maps))
			}

			if maps[0].Source != c.expected {
				t.Errorf("want Source %q; have %q", c.expected, maps[0].Source)
			}
		})
	}
}

func TestGetSourceMapsHTML(t *testing.T) {
	source := "<html><body><script>var x=1;\n//# sourceMappingURL=app.js.map\n</script></body></html>"

	actual := smSummarize(NewAnalyzer([]byte(source)).GetSourceMaps())
	expected := []smSummary{{"sourceMappingURL", "app.js.map", false, 2}}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("want %+v for HTML input; have %+v", expected, actual)
	}
}

func TestGetSourceMapsNeverNil(t *testing.T) {
	var nilAnalyzer *Analyzer
	for name, a := range map[string]*Analyzer{
		"nil analyzer":   nilAnalyzer,
		"zero analyzer":  {},
		"empty source":   NewAnalyzer([]byte{}),
		"no comments":    NewAnalyzer([]byte("var x = 1;")),
		"just a comment": NewAnalyzer([]byte("// hello")),
	} {
		if maps := a.GetSourceMaps(); maps == nil || len(maps) != 0 {
			t.Errorf("%s: want an empty, non-nil slice from GetSourceMaps; have %#v", name, maps)
		}

		if urls := a.GetCommentURLs(); urls == nil || len(urls) != 0 {
			t.Errorf("%s: want an empty, non-nil slice from GetCommentURLs; have %#v", name, urls)
		}
	}
}

func TestSourceMapJSON(t *testing.T) {
	maps := NewAnalyzer([]byte("//# sourceMappingURL=app.js.map")).GetSourceMaps()
	if len(maps) != 1 {
		t.Fatalf("want 1 source map; have %d", len(maps))
	}
	maps[0].Filename = "app.js"

	b, err := json.Marshal(maps[0])
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"kind":"sourceMappingURL","url":"app.js.map","inline":false,"line":1,"source":"//# sourceMappingURL=app.js.map","filename":"app.js"}`
	if string(b) != expected {
		t.Errorf("want %s; have %s", expected, b)
	}

	// inline maps have no URL, and the field is left out
	maps = NewAnalyzer([]byte("//# sourceMappingURL=data:application/json;base64,AAAA")).GetSourceMaps()
	if len(maps) != 1 {
		t.Fatalf("want 1 source map; have %d", len(maps))
	}

	b, err = json.Marshal(maps[0])
	if err != nil {
		t.Fatal(err)
	}

	expected = `{"kind":"sourceMappingURL","inline":true,"line":1,"source":"//# sourceMappingURL=data:application/json;base64,AAAA"}`
	if string(b) != expected {
		t.Errorf("want %s; have %s", expected, b)
	}
}

func TestSourceMapLongInlineMap(t *testing.T) {
	payload := strings.Repeat("QUJD", 5000)
	source := "var x=1;\n//# sourceMappingURL=data:application/json;base64," + payload

	maps := NewAnalyzer([]byte(source)).GetSourceMaps()
	if len(maps) != 1 {
		t.Fatalf("want 1 source map; have %d", len(maps))
	}

	m := maps[0]
	if !m.Inline || m.URL != "" || m.Line != 2 {
		t.Errorf("want an inline map with no URL on line 2; have %+v", summarizeOne(m))
	}

	if len(m.Source) > smMaxSource+len("...") {
		t.Errorf("want Source to be truncated; have %d bytes", len(m.Source))
	}

	if !strings.HasPrefix(m.Source, "//# sourceMappingURL=data:application/json;base64,QUJD") ||
		!strings.HasSuffix(m.Source, "...") {
		t.Errorf("want Source to be the start of the comment with an ellipsis; have %q", m.Source)
	}
}

func summarizeOne(m *SourceMap) smSummary {
	return smSummary{m.Kind, m.URL, m.Inline, m.Line}
}

func TestSourceMapRawScan(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expected []smSummary
	}{
		{
			"trailing comment with no newline",
			"var x=1;\n//# sourceMappingURL=/static/js/main.abc.js.map",
			[]smSummary{{"sourceMappingURL", "/static/js/main.abc.js.map", false, 2}},
		},
		{
			"comment on the same line as code",
			"var x=1; //# sourceMappingURL=a.map",
			[]smSummary{{"sourceMappingURL", "a.map", false, 1}},
		},
		{
			"@ syntax in a block comment",
			"var x=1;\n\n/*@ sourceURL=a.js*/",
			[]smSummary{{"sourceURL", "a.js", false, 3}},
		},
		{
			"opener with a space after it",
			"// # sourceMappingURL=a.map",
			[]smSummary{{"sourceMappingURL", "a.map", false, 1}},
		},

		// a comment opener is required when scanning raw source
		{"no opener", "# sourceMappingURL=a.map", []smSummary{}},
		{"closing a comment is not an opener", "/* x */# sourceMappingURL=a.map", []smSummary{}},
		{"escaped slashes", `\/\/# sourceMappingURL=a.map`, []smSummary{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := smRawScan([]byte(c.source))

			actual := make([]smSummary, 0, len(hits))
			for _, h := range hits {
				actual = append(actual, summarizeOne(h.sm))
			}

			if !reflect.DeepEqual(actual, c.expected) {
				t.Errorf("want %+v for smRawScan(%q); have %+v", c.expected, c.source, actual)
			}
		})
	}
}

func TestSourceMapRawScanLargeInput(t *testing.T) {
	// A big minified bundle, with the reference on the very last line
	// and with no trailing newline. The reference is the only thing
	// on its line, so the line number is that of the last line.
	filler := strings.Repeat("function f(a,b){return a+b}var x=f(1,2),y='#@ source';\n", 5000)
	source := filler + "//# sourceMappingURL=main.js.map"

	maps := NewAnalyzer([]byte(source)).GetSourceMaps()

	actual := smSummarize(maps)
	expected := []smSummary{{"sourceMappingURL", "main.js.map", false, 5001}}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("want %+v for a large input; have %+v", expected, actual)
	}
}

func TestSmSnippet(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		expected string
	}{
		{"empty", "", ""},
		{"short", "//# sourceMappingURL=a.map", "//# sourceMappingURL=a.map"},
		{"exactly the limit", strings.Repeat("a", smMaxSource), strings.Repeat("a", smMaxSource)},
		{"one over the limit", strings.Repeat("a", smMaxSource+1), strings.Repeat("a", smMaxSource) + "..."},
		{"much longer", strings.Repeat("a", 10000), strings.Repeat("a", smMaxSource) + "..."},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual := smSnippet([]byte(c.in))
			if actual != c.expected {
				t.Errorf("want %q; have %q", c.expected, actual)
			}
		})
	}

	// multi-byte characters shouldn't be cut in half
	for _, ch := range []string{"é", "€", "\U0001F600"} {
		actual := smSnippet([]byte(strings.Repeat(ch, 1000)))

		if !utf8.ValidString(actual) {
			t.Errorf("want valid UTF-8 for a truncated string of %q; have %q", ch, actual)
		}

		if len(actual) > smMaxSource+len("...") {
			t.Errorf("want a truncated string of %q to be at most %d bytes; have %d", ch, smMaxSource+len("..."), len(actual))
		}
	}
}

func TestGetCommentURLs(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expected []string
	}{
		{
			"URL and path in a block comment",
			`/* see https://api.example.com/v2/docs and /internal/admin */`,
			[]string{"https://api.example.com/v2/docs", "/internal/admin"},
		},
		{
			"trailing punctuation",
			`// docs live at https://example.com/docs.`,
			[]string{"https://example.com/docs"},
		},
		{
			"URLs wrapped in brackets",
			`// (https://example.com/a) [https://example.com/b], <https://example.com/c>; {@link https://example.com/d}`,
			[]string{
				"https://example.com/a",
				"https://example.com/b",
				"https://example.com/c",
				"https://example.com/d",
			},
		},
		{
			"commented out code",
			"// fetch(\"/api/v1/users/\" + id)\n// $.post('/admin/delete', {id: id})\n// el.href = `/legacy/path`;",
			[]string{"/api/v1/users/", "/admin/delete", "/legacy/path"},
		},
		{
			"key=value",
			`// API_URL=https://api.example.com/v1 and href=/login`,
			[]string{"https://api.example.com/v1", "/login"},
		},
		{
			"query string is kept intact",
			`// try /search?q=test&page=2`,
			[]string{"/search?q=test&page=2"},
		},
		{
			"file names",
			`/* For license information please see main.js.LICENSE.txt */`,
			[]string{"main.js.LICENSE.txt"},
		},
		{
			"JSDoc",
			"/**\n * Fetches the thing.\n * @see https://example.com/docs/fetch\n * @see /api/thing\n */",
			[]string{"https://example.com/docs/fetch", "/api/thing"},
		},
		{
			"protocol-relative",
			`// cdn: //cdn.example.com/lib.js`,
			[]string{"//cdn.example.com/lib.js"},
		},
		{
			"comments in nested scopes, in order of appearance",
			"function f() {\n  var o = {\n    // /nested/path\n    a: 1 /* /inline/path */\n  };\n}\n// /last/path",
			[]string{"/nested/path", "/inline/path", "/last/path"},
		},
		{
			"each URL is returned once",
			"// /api/a\n// see /api/a and /api/b\n/* /api/b */",
			[]string{"/api/a", "/api/b"},
		},

		// not URLs
		{
			"comment delimiters and slashes on their own",
			"/** a / b // c /* d */\n// ---- // ----\n/// /",
			[]string{},
		},
		{
			"prose",
			`// TODO: fix this later (e.g. when v2.0 ships) - see JIRA-123 and/or 1/2`,
			[]string{},
		},
		{
			"code that merely looks a bit like URLs",
			`// .then(res => res.json()).then($('#a').html())`,
			[]string{},
		},
		{
			"w3.org",
			`// xmlns: http://www.w3.org/2000/svg`,
			[]string{},
		},
		{
			"URLs in strings are for GetURLs",
			`var u = "https://example.com/api"; var v = '/admin';`,
			[]string{},
		},
		{
			"source map comments are for GetSourceMaps",
			"//# sourceMappingURL=app.js.map\n//# sourceURL=app.js\n//# sourceMappingURL=https://cdn.example.com/app.js.map\n/*# sourceMappingURL = data:application/json;base64,AAAA */",
			[]string{},
		},
		{
			"no comments",
			`var x = 1;`,
			[]string{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			urls := NewAnalyzer([]byte(c.source)).GetCommentURLs()

			actual := make([]string, 0, len(urls))
			for _, u := range urls {
				actual = append(actual, u.URL)
			}

			if !reflect.DeepEqual(actual, c.expected) {
				t.Errorf("want %q for GetCommentURLs(%q); have %q", c.expected, c.source, actual)
			}
		})
	}
}

func TestGetCommentURLsFields(t *testing.T) {
	source := "var x = 1;\n// see /search?q=test&page=2 for details\n"

	urls := NewAnalyzer([]byte(source)).GetCommentURLs()
	if len(urls) != 1 {
		t.Fatalf("want 1 URL; have %d", len(urls))
	}
	u := urls[0]

	if u.URL != "/search?q=test&page=2" {
		t.Errorf("want URL %q; have %q", "/search?q=test&page=2", u.URL)
	}

	if u.Type != "comment" {
		t.Errorf("want Type %q; have %q", "comment", u.Type)
	}

	if u.Source != "// see /search?q=test&page=2 for details" {
		t.Errorf("want Source to be the comment; have %q", u.Source)
	}

	if !reflect.DeepEqual(u.QueryParams, []string{"page", "q"}) {
		t.Errorf("want QueryParams [page q]; have %v", u.QueryParams)
	}

	// the params are easier to deal with as empty arrays than as nulls
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"queryParams", "bodyParams"} {
		if _, ok := decoded[key].([]any); !ok {
			t.Errorf("want %s to be an array in the JSON output; have %v", key, decoded[key])
		}
	}
}

func TestGetCommentURLsLongComment(t *testing.T) {
	source := "/* see /api/long " + strings.Repeat("lorem ipsum ", 500) + " */"

	urls := NewAnalyzer([]byte(source)).GetCommentURLs()
	if len(urls) != 1 {
		t.Fatalf("want 1 URL; have %d", len(urls))
	}

	if len(urls[0].Source) > smMaxSource+len("...") || !strings.HasSuffix(urls[0].Source, "...") {
		t.Errorf("want Source to be truncated; have %d bytes: %q", len(urls[0].Source), urls[0].Source)
	}
}
