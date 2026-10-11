package jsluice

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// urlmodWant describes the parts of a URL that the tests care about
type urlmodWant struct {
	URL         string
	Type        string
	Method      string
	QueryParams []string
	BodyParams  []string
	Headers     map[string]string
	ContentType string
}

// urlmodNormalize sorts the params (their order isn't guaranteed), and
// turns empty slices and maps into nils so they compare equal
func urlmodNormalize(w urlmodWant) urlmodWant {
	sorted := func(in []string) []string {
		if len(in) == 0 {
			return nil
		}
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}

	w.QueryParams = sorted(w.QueryParams)
	w.BodyParams = sorted(w.BodyParams)
	if len(w.Headers) == 0 {
		w.Headers = nil
	}
	return w
}

func urlmodSummarize(u *URL) urlmodWant {
	return urlmodNormalize(urlmodWant{
		URL:         u.URL,
		Type:        u.Type,
		Method:      u.Method,
		QueryParams: u.QueryParams,
		BodyParams:  u.BodyParams,
		Headers:     u.Headers,
		ContentType: u.ContentType,
	})
}

func urlmodSummarizeAll(urls []*URL) []urlmodWant {
	out := make([]urlmodWant, 0, len(urls))
	for _, u := range urls {
		out = append(out, urlmodSummarize(u))
	}
	return out
}

// urlmodOnlyModern finds URLs using only the modern matchers, so that
// the results aren't muddied by the matchers that existed before them
func urlmodOnlyModern(js string) []*URL {
	a := NewAnalyzer([]byte(js))
	a.DisableDefaultURLMatchers()
	for _, m := range modernURLMatchers() {
		a.AddURLMatcher(m)
	}
	return a.GetURLs()
}

func TestModernURLMatchers(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want []urlmodWant
	}{
		// axios(config)
		{
			name: "axios config",
			js:   `axios({url:"/orders",method:"post",data:{a:1}})`,
			want: []urlmodWant{
				{URL: "/orders", Type: "axios", Method: "POST", BodyParams: []string{"a"}},
			},
		},
		{
			name: "axios config with a template url, params, and headers",
			js: "axios({url: `/orders/${id}`, params: {q: 1, r: 2}, " +
				"headers: {'Content-Type': 'application/json', Authorization: `Bearer ${t}`, 'X-N': n}})",
			want: []urlmodWant{{
				URL:         "/orders/EXPR",
				Type:        "axios",
				Method:      "GET",
				QueryParams: []string{"q", "r"},
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer EXPR",
					"X-N":           "",
				},
				ContentType: "application/json",
			}},
		},
		{
			name: "axios config method is case-insensitive in key and value",
			js:   `axios({url: "/a", Method: "Delete"})`,
			want: []urlmodWant{{URL: "/a", Type: "axios", Method: "DELETE"}},
		},
		{
			name: "axios config with spread",
			js:   `axios({...opts, url: "/spread"})`,
			want: []urlmodWant{{URL: "/spread", Type: "axios", Method: "GET"}},
		},
		{
			name: "axios config with a concatenated url",
			js:   `axios({url: base + "/orders"})`,
			want: []urlmodWant{{URL: "EXPR/orders", Type: "axios", Method: "GET"}},
		},
		{
			name: "axios config with a JSON.stringify data",
			js:   `axios({url: "/j", method: "put", data: JSON.stringify({x: 1, y: 2})})`,
			want: []urlmodWant{{URL: "/j", Type: "axios", Method: "PUT", BodyParams: []string{"x", "y"}}},
		},
		{
			name: "axios config without a url",
			js:   `axios({method: "post"})`,
		},
		{
			name: "axios config with a variable url",
			js:   `axios({url: someVar, method: "post"})`,
		},
		{
			name: "axios config with a shorthand url",
			js:   `axios({url, method: "post"})`,
		},

		// axios(url [, config])
		{
			name: "axios url",
			js:   `axios("/ping")`,
			want: []urlmodWant{{URL: "/ping", Type: "axios", Method: "GET"}},
		},
		{
			name: "axios url with config",
			js:   `axios("/ping", {method: "put", data: {a: 1}, params: {b: 2}})`,
			want: []urlmodWant{{
				URL:         "/ping",
				Type:        "axios",
				Method:      "PUT",
				QueryParams: []string{"b"},
				BodyParams:  []string{"a"},
			}},
		},
		{
			name: "axios with a variable url",
			js:   `axios(url)`,
		},
		{
			name: "axios with no arguments",
			js:   `axios()`,
		},

		// axios.<method>()
		{
			name: "axios.get with params",
			js:   `axios.get("/users",{params:{page:1}})`,
			want: []urlmodWant{{URL: "/users", Type: "axios.get", Method: "GET", QueryParams: []string{"page"}}},
		},
		{
			name: "axios.get merges params with the query string",
			js:   `axios.get("/users?sort=asc", {params: {page: 1}})`,
			want: []urlmodWant{{URL: "/users?sort=asc", Type: "axios.get", Method: "GET", QueryParams: []string{"page", "sort"}}},
		},
		{
			name: "axios.get with a template literal",
			js:   "axios.get(`/users/${id}`)",
			want: []urlmodWant{{URL: "/users/EXPR", Type: "axios.get", Method: "GET"}},
		},
		{
			name: "axios.post with data, params, and headers",
			js: `axios.post("/users", {name: "x", age: 1}, ` +
				`{params: {v: 2}, headers: {"X-A": "b", "content-type": "application/json"}})`,
			want: []urlmodWant{{
				URL:         "/users",
				Type:        "axios.post",
				Method:      "POST",
				QueryParams: []string{"v"},
				BodyParams:  []string{"name", "age"},
				Headers:     map[string]string{"X-A": "b", "content-type": "application/json"},
				ContentType: "application/json",
			}},
		},
		{
			name: "axios.post with a stringified body",
			js:   `axios.post("/users", JSON.stringify({a: 1, b: 2}))`,
			want: []urlmodWant{{URL: "/users", Type: "axios.post", Method: "POST", BodyParams: []string{"a", "b"}}},
		},
		{
			name: "axios.post with a body we can't see into",
			js:   `axios.post("/users", formData)`,
			want: []urlmodWant{{URL: "/users", Type: "axios.post", Method: "POST"}},
		},
		{
			name: "axios.put and axios.patch",
			js:   `axios.put("/p", {a: 1}); axios.patch("/q", {b: 1})`,
			want: []urlmodWant{
				{URL: "/p", Type: "axios.put", Method: "PUT", BodyParams: []string{"a"}},
				{URL: "/q", Type: "axios.patch", Method: "PATCH", BodyParams: []string{"b"}},
			},
		},
		{
			name: "axios.delete with data in the config",
			js:   `axios.delete("/users/1", {data: {reason: "x"}})`,
			want: []urlmodWant{{URL: "/users/1", Type: "axios.delete", Method: "DELETE", BodyParams: []string{"reason"}}},
		},
		{
			name: "axios.head and axios.options",
			js:   `axios.head("/h"); axios.options("/o")`,
			want: []urlmodWant{
				{URL: "/h", Type: "axios.head", Method: "HEAD"},
				{URL: "/o", Type: "axios.options", Method: "OPTIONS"},
			},
		},
		{
			name: "axios.postForm",
			js:   `axios.postForm("/upload", {file: f})`,
			want: []urlmodWant{{URL: "/upload", Type: "axios.postForm", Method: "POST", BodyParams: []string{"file"}}},
		},
		{
			name: "axios.request with a config",
			js:   `axios.request({url: "/r", method: "patch"})`,
			want: []urlmodWant{{URL: "/r", Type: "axios.request", Method: "PATCH"}},
		},
		{
			name: "axios.request with a url",
			js:   `axios.request("/r", {method: "put"})`,
			want: []urlmodWant{{URL: "/r", Type: "axios.request", Method: "PUT"}},
		},
		{
			name: "axios by other names",
			js:   `this.$axios.get("/nuxt"); window.axios.post("/w"); this.axios({url: "/c"})`,
			want: []urlmodWant{
				{URL: "/nuxt", Type: "this.$axios.get", Method: "GET"},
				{URL: "/w", Type: "window.axios.post", Method: "POST"},
				{URL: "/c", Type: "axios", Method: "GET"},
			},
		},
		{
			name: "axios in an async function",
			js:   `async function f() { const r = await axios.get("/awaited"); return r }`,
			want: []urlmodWant{{URL: "/awaited", Type: "axios.get", Method: "GET"}},
		},
		{
			name: "axios.get with a variable url",
			js:   `axios.get(url, {params: {a: 1}})`,
		},
		{
			name: "not axios",
			js: `axios.create({baseURL: "/api"}); axios.all([a, b]); axios.isCancel(e); ` +
				`myaxios.get("/x"); foo.axios2.get("/x"); store.get("/x"); axiosish("/x")`,
		},

		// WebSocket, EventSource, Request
		{
			name: "WebSocket",
			js:   `new WebSocket("wss://e.com/s")`,
			want: []urlmodWant{{URL: "wss://e.com/s", Type: "websocket", Method: "GET"}},
		},
		{
			name: "WebSocket with a template literal and protocols",
			js:   "new WebSocket(`wss://${host}/live/${room}`, ['v1'])",
			want: []urlmodWant{{URL: "wss://EXPR/live/EXPR", Type: "websocket", Method: "GET"}},
		},
		{
			name: "WebSocket by way of a global object",
			js:   `new window.WebSocket("/ws"); new self.WebSocket("/ws2"); new globalThis.WebSocket("/ws3")`,
			want: []urlmodWant{
				{URL: "/ws", Type: "websocket", Method: "GET"},
				{URL: "/ws2", Type: "websocket", Method: "GET"},
				{URL: "/ws3", Type: "websocket", Method: "GET"},
			},
		},
		{
			name: "EventSource",
			js:   `new EventSource("/stream")`,
			want: []urlmodWant{{URL: "/stream", Type: "eventSource", Method: "GET"}},
		},
		{
			name: "Request",
			js:   `new Request("/x")`,
			want: []urlmodWant{{URL: "/x", Type: "request", Method: "GET"}},
		},
		{
			name: "Request with an init object",
			js: `new Request("/x", {method: "post", headers: {"X-A": "b", "Content-Type": "text/plain"}, ` +
				`body: JSON.stringify({q: 1})})`,
			want: []urlmodWant{{
				URL:         "/x",
				Type:        "request",
				Method:      "POST",
				BodyParams:  []string{"q"},
				Headers:     map[string]string{"X-A": "b", "Content-Type": "text/plain"},
				ContentType: "text/plain",
			}},
		},
		{
			name: "Request with Headers",
			js:   "new Request(`/x/${id}`, {headers: new Headers({'X-A': 'b'})})",
			want: []urlmodWant{{
				URL:     "/x/EXPR",
				Type:    "request",
				Method:  "GET",
				Headers: map[string]string{"X-A": "b"},
			}},
		},
		{
			name: "constructors that are not interesting, or have no usable url",
			js: `new Foo("/x"); new WebSocket(url); new WebSocket(); new WebSocket; new Request(req); ` +
				`new Request(req, {method: "POST"}); new a.b.WebSocket("/x"); new EventSource(src); ` +
				`new (getCtor())("/x"); new WebSocketish("/x")`,
		},

		// navigator.sendBeacon
		{
			name: "sendBeacon",
			js:   `navigator.sendBeacon("/t", d)`,
			want: []urlmodWant{{URL: "/t", Type: "navigator.sendBeacon", Method: "POST"}},
		},
		{
			name: "sendBeacon with a stringified body",
			js:   `window.navigator.sendBeacon("/collect", JSON.stringify({event: "view", page: p}))`,
			want: []urlmodWant{{
				URL:        "/collect",
				Type:       "navigator.sendBeacon",
				Method:     "POST",
				BodyParams: []string{"event", "page"},
			}},
		},
		{
			name: "sendBeacon with a variable url",
			js:   `navigator.sendBeacon(url, d); sendBeacon("/x", d)`,
		},

		// dynamic import()
		{
			name: "import",
			js:   `import("./chunk.js")`,
			want: []urlmodWant{{URL: "./chunk.js", Type: "dynamicImport", Method: "GET"}},
		},
		{
			name: "import with a webpack comment",
			js:   `import(/* webpackChunkName: "admin" */ "./admin.js")`,
			want: []urlmodWant{{URL: "./admin.js", Type: "dynamicImport", Method: "GET"}},
		},
		{
			name: "import with a template literal",
			js:   "import(`./pages/${name}.js`)",
			want: []urlmodWant{{URL: "./pages/EXPR.js", Type: "dynamicImport", Method: "GET"}},
		},
		{
			name: "import with a concatenation",
			js:   `import("./locale/" + lang + ".js")`,
			want: []urlmodWant{{URL: "./locale/EXPR.js", Type: "dynamicImport", Method: "GET"}},
		},
		{
			name: "import with no usable url",
			js:   `import(x); import(); import(/* only a comment */); import foo from "./static.js"`,
		},

		// importScripts()
		{
			name: "importScripts returns the first url",
			js:   `importScripts("a.js", "b.js")`,
			want: []urlmodWant{{URL: "a.js", Type: "importScripts", Method: "GET"}},
		},
		{
			name: "importScripts skips arguments that don't start with a string",
			js:   `importScripts(base + "a.js", "/b.js")`,
			want: []urlmodWant{{URL: "/b.js", Type: "importScripts", Method: "GET"}},
		},
		{
			name: "importScripts on self",
			js:   `self.importScripts("/w.js")`,
			want: []urlmodWant{{URL: "/w.js", Type: "importScripts", Method: "GET"}},
		},
		{
			name: "importScripts with no usable url",
			js:   `importScripts(x); importScripts()`,
		},

		// Angular HttpClient
		{
			name: "http.get",
			js:   `this.http.get("/api/items")`,
			want: []urlmodWant{{URL: "/api/items", Type: "this.http.get", Method: "GET"}},
		},
		{
			name: "http.get with params",
			js:   `this.http.get("/api/items", {params: {sort: "asc"}})`,
			want: []urlmodWant{{URL: "/api/items", Type: "this.http.get", Method: "GET", QueryParams: []string{"sort"}}},
		},
		{
			name: "http.post with a body, params, and headers",
			js: "this.http.post(`/api/items/${id}`, {name: n, qty: 2}, " +
				"{params: {a: 1}, headers: new HttpHeaders({'Content-Type': 'application/json'})})",
			want: []urlmodWant{{
				URL:         "/api/items/EXPR",
				Type:        "this.http.post",
				Method:      "POST",
				QueryParams: []string{"a"},
				BodyParams:  []string{"name", "qty"},
				Headers:     map[string]string{"Content-Type": "application/json"},
				ContentType: "application/json",
			}},
		},
		{
			name: "http.request takes the method first",
			js:   `this.http.request("DELETE", "/api/items/1")`,
			want: []urlmodWant{{URL: "/api/items/1", Type: "this.http.request", Method: "DELETE"}},
		},
		{
			name: "http.request with options",
			js:   `this.http.request("get", "/api/items", {params: {a: 1}})`,
			want: []urlmodWant{{URL: "/api/items", Type: "this.http.request", Method: "GET", QueryParams: []string{"a"}}},
		},
		{
			name: "http.request with a body in the options",
			js:   `this.http.request("POST", "/api/items", {body: {a: 1}, params: {b: 2}})`,
			want: []urlmodWant{{
				URL:         "/api/items",
				Type:        "this.http.request",
				Method:      "POST",
				QueryParams: []string{"b"},
				BodyParams:  []string{"a"},
			}},
		},
		{
			name: "http.request with a method but no literal url",
			js:   `this.http.request("GET", url); this.http.request("GET")`,
		},
		{
			name: "http.jsonp",
			js:   `this.http.jsonp("/jsonp", "callback")`,
			want: []urlmodWant{{URL: "/jsonp", Type: "this.http.jsonp", Method: "GET"}},
		},
		{
			name: "http by other names",
			js: `http.get("/a"); this._http.put("/b", {x: 1}); this.httpClient.delete("/c"); ` +
				`this._httpClient.head("/d")`,
			want: []urlmodWant{
				{URL: "/a", Type: "http.get", Method: "GET"},
				{URL: "/b", Type: "this._http.put", Method: "PUT", BodyParams: []string{"x"}},
				{URL: "/c", Type: "this.httpClient.delete", Method: "DELETE"},
				{URL: "/d", Type: "this._httpClient.head", Method: "HEAD"},
			},
		},
		{
			name: "http call split over multiple lines",
			js:   "this.http\n    .get('/multi')",
			want: []urlmodWant{{URL: "/multi", Type: "this.http.get", Method: "GET"}},
		},
		{
			name: "http call with optional chaining",
			js:   `this.http?.get("/optional")`,
			want: []urlmodWant{{URL: "/optional", Type: "this.http.get", Method: "GET"}},
		},
		{
			name: "not HttpClient",
			js: "cache.get('/x'); this.httpService.get('/x'); this.http.get(url); this.http.pipe('/x'); " +
				"http.get`/x`; this.http.request(new HttpRequest('GET', '/x')); http.cache.get('/x')",
		},

		// odds and ends
		{
			name: "calls that can't name an API are left alone",
			js:   `(function() { return "/x" })(); (() => axios.get)()("/y"); a[b]("/z"); foo()("/q")`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			urls := urlmodOnlyModern(c.js)

			got := urlmodSummarizeAll(urls)
			want := make([]urlmodWant, 0, len(c.want))
			for _, w := range c.want {
				want = append(want, urlmodNormalize(w))
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("unexpected URLs for %q\nwant: %+v\nhave: %+v", c.js, want, got)
			}

			// A Source is useful if you want to find out where a
			// URL came from, so every match needs one
			for _, u := range urls {
				if u.Source == "" || !strings.Contains(c.js, u.Source) {
					t.Errorf("want Source for %q to be a non-empty part of %q", u.URL, c.js)
				}
			}
		})
	}
}

// TestGetURLsModern runs everything through the default matchers
func TestGetURLsModern(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want urlmodWant
	}{
		{
			name: "fetch with a template literal",
			js:   "fetch(`/api/v2/users/${id}/profile?x=1`)",
			want: urlmodWant{
				URL:         "/api/v2/users/EXPR/profile?x=1",
				Type:        "fetch",
				Method:      "GET",
				QueryParams: []string{"x"},
			},
		},
		{
			name: "axios config",
			js:   `axios({url:"/orders",method:"post",data:{a:1}})`,
			want: urlmodWant{URL: "/orders", Type: "axios", Method: "POST", BodyParams: []string{"a"}},
		},
		{
			name: "axios.get",
			js:   `axios.get("/users",{params:{page:1}})`,
			want: urlmodWant{URL: "/users", Type: "axios.get", Method: "GET", QueryParams: []string{"page"}},
		},
		{
			name: "WebSocket",
			js:   `new WebSocket("wss://e.com/s")`,
			want: urlmodWant{URL: "wss://e.com/s", Type: "websocket", Method: "GET"},
		},
		{
			name: "EventSource",
			js:   `new EventSource("/stream")`,
			want: urlmodWant{URL: "/stream", Type: "eventSource", Method: "GET"},
		},
		{
			name: "dynamic import",
			js:   `import("./chunk.js")`,
			want: urlmodWant{URL: "./chunk.js", Type: "dynamicImport", Method: "GET"},
		},
		{
			name: "sendBeacon",
			js:   `navigator.sendBeacon("/t",d)`,
			want: urlmodWant{URL: "/t", Type: "navigator.sendBeacon", Method: "POST"},
		},
		{
			name: "Request",
			js:   `fetch(new Request("/r", {method: "PUT"}))`,
			want: urlmodWant{URL: "/r", Type: "request", Method: "PUT"},
		},
		{
			name: "template literals in the existing matchers",
			js:   "xhr.open('POST', `/api/${a}/save?v=1`)",
			want: urlmodWant{
				URL:         "/api/EXPR/save?v=1",
				Type:        "XMLHttpRequest.open",
				Method:      "POST",
				QueryParams: []string{"v"},
			},
		},
		{
			name: "template literal location assignment",
			js:   "location.href = `/account/${id}/settings`",
			want: urlmodWant{URL: "/account/EXPR/settings", Type: "locationAssignment", Method: "GET"},
		},
		{
			name: "WebSocket string literal",
			js:   `var s = "wss://e.com/socket"`,
			want: urlmodWant{URL: "wss://e.com/socket", Type: "stringLiteral"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewAnalyzer([]byte(c.js)).GetURLs()

			want := urlmodNormalize(c.want)
			for _, u := range got {
				if reflect.DeepEqual(urlmodSummarize(u), want) {
					return
				}
			}

			t.Errorf("no match for %q\nwant: %+v\nhave: %+v", c.js, want, urlmodSummarizeAll(got))
		})
	}
}

// TestGetURLsModernExpressionOnly makes sure that the URLs that are
// nothing but placeholders are still dropped now templates are collapsed
func TestGetURLsModernExpressionOnly(t *testing.T) {
	js := "fetch(`${a}${b}`); new WebSocket(`${url}`); axios.get(`${u}`); import(`${p}`)"

	for _, u := range NewAnalyzer([]byte(js)).GetURLs() {
		t.Errorf("want no URLs for %q, have: %+v", js, u)
	}
}

// TestModernURLMatchersOrder checks that the modern matchers sit between the
// existing specific matchers and the matchers that provide the least context.
func TestModernURLMatchersOrder(t *testing.T) {
	all := AllURLMatchers()

	// The string literal matcher provides the least context
	// of all so it needs to stay at the very end.
	last := all[len(all)-1]
	if last.Type != "string" {
		t.Fatalf("want the last matcher to have type string; have %s", last.Type)
	}
	parsed := NewAnalyzer([]byte(`"/some/path.php"`))
	parsed.Query("(string) @s", func(n *Node) {
		match := last.Fn(n)
		if match == nil || match.Type != "stringLiteral" {
			t.Errorf("want the last matcher to be the string literal matcher; have: %+v", match)
		}
	})

	// All of the modern matchers need to be registered
	for _, m := range modernURLMatchers() {
		found := false
		for _, candidate := range all {
			if candidate.Type == m.Type && reflect.ValueOf(candidate.Fn).Pointer() == reflect.ValueOf(m.Fn).Pointer() {
				found = true
			}
		}
		if !found {
			t.Errorf("want a %s modern matcher to be registered", m.Type)
		}
	}

	// De-duplicating by URL keeps whichever match came first (which is what
	// the --unique flag does), so the match with the most context needs to be
	// the first one for any given URL. That's the modern match, not the one
	// from the matcher for 'other function calls' that knows nothing about
	// the method or the params.
	cases := []struct {
		js   string
		want urlmodWant
	}{
		{
			js:   `axios.get("/users", {params: {page: 1}})`,
			want: urlmodWant{URL: "/users", Type: "axios.get", Method: "GET", QueryParams: []string{"page"}},
		},
		{
			js:   `navigator.sendBeacon("/t", JSON.stringify({a: 1}))`,
			want: urlmodWant{URL: "/t", Type: "navigator.sendBeacon", Method: "POST", BodyParams: []string{"a"}},
		},
		{
			js:   `import("./chunk.js")`,
			want: urlmodWant{URL: "./chunk.js", Type: "dynamicImport", Method: "GET"},
		},
		{
			js:   `new WebSocket("wss://e.com/s")`,
			want: urlmodWant{URL: "wss://e.com/s", Type: "websocket", Method: "GET"},
		},
	}

	for _, c := range cases {
		urls := NewAnalyzer([]byte(c.js)).GetURLs()
		if len(urls) == 0 {
			t.Errorf("want URLs for %q; have none", c.js)
			continue
		}

		want := urlmodNormalize(c.want)
		if got := urlmodSummarize(urls[0]); !reflect.DeepEqual(got, want) {
			t.Errorf("want the first URL for %q to be %+v; have %+v", c.js, want, got)
		}
	}
}

// TestModernURLMatchersTruncated runs every prefix of some realistic code
// through the matchers. Cutting code off part way through is a good way to
// find the nodes and fields that go missing in a broken syntax tree.
func TestModernURLMatchersTruncated(t *testing.T) {
	sources := []string{
		"axios.post(`/users/${id}/notes`, {text: t}, {params: {v: 2}, headers: {'Content-Type': 'application/json'}});",
		"axios({url: '/orders', method: 'post', data: {a: 1}, params: {b: 2}}); axios('/ping', {method: 'put'});",
		"new WebSocket(`wss://${host}/live`); new EventSource('/stream'); new Request('/x', {method: 'POST', body: JSON.stringify({q: 1})});",
		"navigator.sendBeacon('/collect', JSON.stringify({event: 'view'})); import(/* webpackChunkName: 'a' */ './a.js'); importScripts('a.js', 'b.js');",
		"this.http\n  ?.post('/api/items', {name: n}, {headers: new HttpHeaders({'A': `B ${c}`})}); this.http.request('GET', '/x');",
	}

	for _, src := range sources {
		for i := 0; i <= len(src); i++ {
			js := src[:i]

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic for %q: %v", js, r)
					}
				}()
				NewAnalyzer([]byte(js)).GetURLs()
			}()
		}
	}
}

// TestModernURLMatchersMalformed makes sure that unusual or broken
// code doesn't cause a panic. Tree-sitter will happily produce a syntax
// tree for it, but with missing nodes and fields.
func TestModernURLMatchersMalformed(t *testing.T) {
	inputs := []string{
		"axios(",
		"axios.get(",
		"axios.get(,)",
		"axios({url:",
		"axios({url: `",
		"new WebSocket(",
		"new WebSocket",
		"new (",
		"new Request(,",
		"import(",
		"import",
		"importScripts(",
		"navigator.sendBeacon(",
		"this.http.get(",
		"this.http.request(",
		"this.http.request('GET'",
		"`",
		"`${",
		"`${}`",
		"fetch(`${`",
		"x = `/a/${",
		"axios.get`/x`",
		"http.post`/x/${y}`",
		"new Foo.Bar.Baz('/x')",
		"import.meta.url",
		"axios({url: '/a', params: x, data: y, headers: z})",
		"axios({url: '/a', headers: {a: b, [c]: d, ...e}})",
		"axios.post('/a', ...args)",
		"new Request('/a', ...args)",
		"(function(){ axios.get('/in-iife') })()",
		"<html><script>axios.get('/in-html')</script></html>",
	}

	for _, js := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic for %q: %v", js, r)
				}
			}()
			NewAnalyzer([]byte(js)).GetURLs()
		}()
	}
}
