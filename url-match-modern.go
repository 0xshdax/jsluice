package jsluice

import (
	"strings"
)

// urlmodMaxName is the longest callee or constructor (in bytes) that we will
// copy out of the source to compare against the names of well-known APIs.
// Anything longer is an inline function or similar and can't be one of them.
const urlmodMaxName = 128

var (
	// Names that axios is commonly referred to by, e.g. axios.get() or
	// this.$axios.get() as used by Nuxt.
	urlmodAxiosNames = newSet([]string{"axios", "$axios"})

	// Names that Angular's HttpClient is commonly injected as,
	// e.g. this.http.get(). This is deliberately a short list; matching
	// anything that has a .get() method would be a recipe for noise.
	urlmodHTTPClientNames = newSet([]string{"http", "_http", "httpClient", "_httpClient"})

	urlmodAxiosVerbs = newSet([]string{
		"get", "post", "put", "patch", "delete", "head", "options", "request",
		"postForm", "putForm", "patchForm",
	})

	urlmodHTTPClientVerbs = newSet([]string{
		"get", "post", "put", "patch", "delete", "head", "options", "request", "jsonp",
	})

	// Verbs that accept a request body as the second argument:
	//   verb(url, data [, config])
	urlmodBodyVerbs = newSet([]string{
		"post", "put", "patch", "postForm", "putForm", "patchForm",
	})

	// The HTTP method implied by the name of the function being called.
	// request() is not really a method at all, so it defaults to GET unless
	// the arguments say otherwise.
	urlmodVerbMethods = map[string]string{
		"get":       "GET",
		"delete":    "DELETE",
		"head":      "HEAD",
		"options":   "OPTIONS",
		"jsonp":     "GET",
		"request":   "GET",
		"post":      "POST",
		"put":       "PUT",
		"patch":     "PATCH",
		"postForm":  "POST",
		"putForm":   "PUT",
		"patchForm": "PATCH",
	}

	// Strings that can be the first argument of HttpClient.request()
	urlmodHTTPMethods = newSet([]string{
		"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "JSONP",
	})
)

// modernURLMatchers returns URLMatchers for the URL-bearing APIs that are
// common in modern JavaScript, but which the original matchers know nothing
// about:
//
//	axios(config), axios(url [, config]), axios.get(url [, config]) etc.
//	Angular's HttpClient: this.http.get(url [, options]) etc.
//	new WebSocket(url), new EventSource(url), new Request(url [, init])
//	navigator.sendBeacon(url [, data])
//	import(url) and importScripts(url [, ...])
//
// URLs are collapsed with Node.CollapsedString, so template literals like
// axios.get(`/users/${id}`) are returned as /users/EXPR.
//
// There is one matcher per node type that does its own dispatching. The
// matchers all want to know what is being called, and working that out once
// per node rather than once per matcher keeps things quick on large bundles.
func modernURLMatchers() []URLMatcher {
	return []URLMatcher{
		{Type: "call_expression", Fn: urlmodMatchCall},
		{Type: "new_expression", Fn: urlmodMatchNew},
	}
}

// urlmodMatchCall matches the call_expression based APIs
func urlmodMatchCall(n *Node) *URL {
	callName := urlmodName(n.ChildByFieldName("function"))
	if callName == "" {
		return nil
	}

	switch {
	case callName == "import":
		return urlmodDynamicImport(n)
	case callName == "importScripts" || strings.HasSuffix(callName, ".importScripts"):
		return urlmodImportScripts(n)
	case strings.HasSuffix(callName, ".sendBeacon"):
		return urlmodSendBeacon(n)
	}

	// Split e.g. this.$axios.get into the name of the object the method is
	// being called on (the last part of the receiver, $axios), and the name
	// of the method (get).
	receiver, name := "", callName
	if i := strings.LastIndexByte(callName, '.'); i >= 0 {
		receiver, name = callName[:i], callName[i+1:]
	}

	// axios(config) and axios(url [, config])
	if urlmodAxiosNames.Contains(name) {
		return urlmodAxios(n)
	}

	owner := receiver
	if i := strings.LastIndexByte(receiver, '.'); i >= 0 {
		owner = receiver[i+1:]
	}

	switch {
	case urlmodAxiosNames.Contains(owner) && urlmodAxiosVerbs.Contains(name):
		return urlmodRESTCall(n, callName, name)
	case urlmodHTTPClientNames.Contains(owner) && urlmodHTTPClientVerbs.Contains(name):
		return urlmodRESTCall(n, callName, name)
	}

	return nil
}

// urlmodMatchNew matches the new_expression based APIs
func urlmodMatchNew(n *Node) *URL {
	name := urlmodName(n.ChildByFieldName("constructor"))
	if name == "" {
		return nil
	}

	// new window.WebSocket() is the same as new WebSocket()
	for _, prefix := range []string{"window.", "self.", "globalThis."} {
		name = strings.TrimPrefix(name, prefix)
	}

	var typ string
	switch name {
	case "WebSocket":
		typ = "websocket"
	case "EventSource":
		typ = "eventSource"
	case "Request":
		typ = "request"
	default:
		return nil
	}

	args := urlmodArgs(n)

	urlArg := urlmodArg(args, 0)
	if !urlArg.IsStringy() {
		return nil
	}

	u := &URL{
		URL:    urlArg.CollapsedString(),
		Method: "GET",
		Type:   typ,
		Source: n.Content(),
	}

	if typ != "request" {
		return u
	}

	// new Request(url [, options]); the options are the same as the
	// ones for fetch(), so there's a method, headers, and a body
	options := urlmodArg(args, 1).AsObject()
	if method := options.GetStringI("method", ""); method != "" {
		u.Method = strings.ToUpper(method)
	}
	u.BodyParams = urlmodBodyKeys(options.GetNode("body"))
	urlmodApplyHeaders(u, options)

	return u
}

// urlmodAxios handles calls to axios itself:
//
//	axios(config)
//	axios(url [, config])
func urlmodAxios(n *Node) *URL {
	args := urlmodArgs(n)
	first := urlmodArg(args, 0)

	if first.Type() == "object" {
		return urlmodConfigCall(n, "axios", first)
	}

	if !first.IsStringy() {
		return nil
	}

	u := &URL{
		URL:    first.CollapsedString(),
		Method: "GET",
		Type:   "axios",
		Source: n.Content(),
	}

	config := urlmodArg(args, 1).AsObject()
	if method := config.GetStringI("method", ""); method != "" {
		u.Method = strings.ToUpper(method)
	}
	urlmodApplyConfig(u, config)

	return u
}

// urlmodRESTCall handles the method style calls of axios and Angular's
// HttpClient. They share the same conventions, with the exception of request():
//
//	get(url [, config]), delete, head, options, jsonp
//	post(url [, data [, config]]), put, patch
//	request(config)                      for axios
//	request(method, url [, options])     for HttpClient
func urlmodRESTCall(n *Node, callName, verb string) *URL {
	args := urlmodArgs(n)
	method := urlmodVerbMethods[verb]

	var urlArg, dataArg, config *Node

	switch {
	case urlmodBodyVerbs.Contains(verb):
		urlArg, dataArg, config = urlmodArg(args, 0), urlmodArg(args, 1), urlmodArg(args, 2)

	case verb == "request":
		first := urlmodArg(args, 0)

		switch {
		case first.Type() == "object":
			return urlmodConfigCall(n, callName, first)

		case urlmodIsHTTPMethod(first):
			// The first argument is the method and not the URL, so there
			// is nothing to be found if the second one isn't a string.
			// The third argument is options rather than a body.
			method = strings.ToUpper(first.RawString())
			urlArg, dataArg, config = urlmodArg(args, 1), &Node{}, urlmodArg(args, 2)

		default:
			urlArg, dataArg, config = first, &Node{}, urlmodArg(args, 1)
			if m := config.AsObject().GetStringI("method", ""); m != "" {
				method = strings.ToUpper(m)
			}
		}

	default:
		urlArg, dataArg, config = urlmodArg(args, 0), &Node{}, urlmodArg(args, 1)
	}

	if !urlArg.IsStringy() {
		return nil
	}

	u := &URL{
		URL:        urlArg.CollapsedString(),
		Method:     method,
		BodyParams: urlmodBodyKeys(dataArg),
		Type:       callName,
		Source:     n.Content(),
	}
	urlmodApplyConfig(u, config.AsObject())

	return u
}

// urlmodConfigCall handles calls where all the details of the request are
// provided by a single config object, e.g. axios({url, method, params, data})
func urlmodConfigCall(n *Node, typ string, config *Node) *URL {
	cfg := config.AsObject()

	urlNode := cfg.GetNode("url")
	if !urlNode.IsValid() {
		return nil
	}

	u := &URL{
		URL:    urlNode.CollapsedString(),
		Method: strings.ToUpper(cfg.GetStringI("method", "GET")),
		Type:   typ,
		Source: n.Content(),
	}
	urlmodApplyConfig(u, cfg)

	return u
}

// urlmodApplyConfig adds the query parameters, body parameters, and headers
// found in an axios or HttpClient style config object to a URL.
func urlmodApplyConfig(u *URL, cfg Object) {
	if !cfg.HasValidNode() {
		return
	}

	u.QueryParams = append(u.QueryParams, cfg.GetObject("params").GetKeys()...)

	// The body is data for axios and body for HttpClient. It only
	// applies here if it was not already provided as an argument.
	if len(u.BodyParams) == 0 {
		u.BodyParams = urlmodBodyKeys(cfg.GetNode("data"))
	}
	if len(u.BodyParams) == 0 {
		u.BodyParams = urlmodBodyKeys(cfg.GetNode("body"))
	}

	urlmodApplyHeaders(u, cfg)
}

// urlmodApplyHeaders adds the headers, and the content type if one of
// the headers is a Content-Type header, to a URL.
func urlmodApplyHeaders(u *URL, cfg Object) {
	headers := urlmodHeaders(cfg.GetNode("headers"))
	if len(headers) == 0 {
		return
	}

	u.Headers = headers
	for name, value := range headers {
		if strings.EqualFold(name, "content-type") {
			u.ContentType = value
		}
	}
}

// urlmodHeaders returns the headers declared by a node that is either an
// object literal, or a call to the Headers/HttpHeaders constructor with an
// object literal. Unlike Object.AsMap, values are collapsed so that a
// template literal like `Bearer ${token}` is reported as Bearer EXPR rather
// than as an empty string. Other kinds of values are reported as empty.
func urlmodHeaders(node *Node) map[string]string {
	out := make(map[string]string)
	if !node.IsValid() {
		return out
	}

	if node.Type() == "new_expression" {
		switch urlmodName(node.ChildByFieldName("constructor")) {
		case "Headers", "HttpHeaders":
			node = urlmodArg(urlmodArgs(node), 0)
		default:
			return out
		}
	}

	obj := node.AsObject()
	for _, key := range obj.GetKeys() {
		value := ""
		if v := obj.GetNode(key); v.IsValid() && v.IsStringy() {
			value = v.CollapsedString()
		}
		out[key] = value
	}
	return out
}

// urlmodBodyKeys returns the keys of an object literal that is used as a
// request body, either directly or by way of JSON.stringify(). Any other kind
// of body doesn't tell us anything about the names of the parameters.
func urlmodBodyKeys(node *Node) []string {
	if !node.IsValid() {
		return nil
	}

	switch node.Type() {
	case "object":
		return node.AsObject().GetKeys()
	case "call_expression":
		if urlmodName(node.ChildByFieldName("function")) == "JSON.stringify" {
			return urlmodBodyKeys(urlmodArg(urlmodArgs(node), 0))
		}
	}
	return nil
}

// urlmodDynamicImport handles import(url)
func urlmodDynamicImport(n *Node) *URL {
	first := urlmodArg(urlmodArgs(n), 0)
	if !first.IsStringy() {
		return nil
	}

	return &URL{
		URL:    first.CollapsedString(),
		Method: "GET",
		Type:   "dynamicImport",
		Source: n.Content(),
	}
}

// urlmodImportScripts handles importScripts(url [, ...]). A URLMatcher can
// only return a single URL, so that's the first of the arguments to look like
// one. The others will still be found as string literals if they look enough
// like URLs.
func urlmodImportScripts(n *Node) *URL {
	for _, arg := range urlmodArgs(n) {
		if !arg.IsStringy() {
			continue
		}

		return &URL{
			URL:    arg.CollapsedString(),
			Method: "GET",
			Type:   "importScripts",
			Source: n.Content(),
		}
	}
	return nil
}

// urlmodSendBeacon handles navigator.sendBeacon(url [, data])
func urlmodSendBeacon(n *Node) *URL {
	args := urlmodArgs(n)

	first := urlmodArg(args, 0)
	if !first.IsStringy() {
		return nil
	}

	return &URL{
		URL:        first.CollapsedString(),
		Method:     "POST",
		BodyParams: urlmodBodyKeys(urlmodArg(args, 1)),
		Type:       "navigator.sendBeacon",
		Source:     n.Content(),
	}
}

// urlmodName returns the source for a callee or constructor node, but only when
// it's a plain name: an identifier, a chain of member expressions like
// this.http.get, or the import keyword; the only things that can name an API.
// Whitespace is removed and optional chaining is normalised, so these all
// give the name this.http.get:
//
//	this.http.get
//	this.http?.get
//	this.http
//	    .get
//
// An empty string is returned for anything else. Every call and constructor in
// a file comes through here, and most of them are not interesting, so the
// checks are done on the bytes of the source before anything is copied. That
// avoids allocating for each one, and means the source of what could be a huge
// inline function is never copied.
func urlmodName(fn *Node) string {
	if !fn.IsValid() {
		return ""
	}

	start, end := int(fn.node.StartByte()), int(fn.node.EndByte())
	if end <= start || end-start > urlmodMaxName || end > len(fn.source) {
		return ""
	}

	raw := fn.source[start:end]
	for _, b := range raw {
		if !urlmodIsNameByte(b) {
			return ""
		}
	}

	name := string(raw)
	if strings.ContainsAny(name, " \t\r\n") {
		name = strings.Join(strings.Fields(name), "")
	}
	return strings.ReplaceAll(name, "?.", ".")
}

// urlmodIsNameByte returns true for the bytes that can be found in a name like
// this.http?.get: identifier characters (including the bytes of any non-ASCII
// ones), dots, the question mark of optional chaining, and whitespace.
func urlmodIsNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '$', b == '.', b == '?', b >= 0x80:
		return true
	case b == ' ', b == '\t', b == '\r', b == '\n':
		return true
	}
	return false
}

// urlmodArgs returns the arguments of a call_expression or new_expression,
// leaving out any comments, which tree-sitter treats as named children. E.g:
//
//	import(/* webpackChunkName: "chunk" */ "./chunk.js")
//
// No arguments are returned for tagged templates, where the arguments field
// is the template_string rather than an arguments node.
func urlmodArgs(n *Node) []*Node {
	args := n.ChildByFieldName("arguments")
	if !args.IsValid() || args.Type() != "arguments" {
		return nil
	}

	out := make([]*Node, 0, args.NamedChildCount())
	for _, arg := range args.NamedChildren() {
		if !arg.IsValid() || arg.Type() == "comment" {
			continue
		}
		out = append(out, arg)
	}
	return out
}

// urlmodArg returns the argument at the provided index, or an empty Node
// if there isn't one. The empty Node is safe to call methods like IsStringy,
// CollapsedString, and AsObject on, so missing arguments need no special care.
func urlmodArg(args []*Node, index int) *Node {
	if index < 0 || index >= len(args) {
		return &Node{}
	}
	return args[index]
}

// urlmodIsHTTPMethod returns true if a node is a string
// containing the name of an HTTP method; e.g. "POST".
func urlmodIsHTTPMethod(n *Node) bool {
	if n.Type() != "string" {
		return false
	}
	return urlmodHTTPMethods.Contains(strings.ToUpper(n.RawString()))
}
