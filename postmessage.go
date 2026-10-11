package jsluice

import (
	"regexp"
	"strings"
	"unicode/utf8"

	sitter "github.com/smacker/go-tree-sitter"
)

// The kinds of MessageListener
const (
	pmKindAddEventListener = "addEventListener"
	pmKindOnMessage        = "onmessage"
	pmKindSend             = "postMessageSend"

	// pmMaxSource is the length at which MessageListener.Source is truncated
	pmMaxSource = 500

	// pmMaxHops is the number of references (identifier -> variable ->
	// .bind() and so on) that are followed to find a message handler
	pmMaxHops = 6
)

// A MessageListener is a place where JavaScript receives or sends
// a cross-origin message using the postMessage API.
type MessageListener struct {
	// One of "addEventListener" or "onmessage" for code that receives
	// messages, or "postMessageSend" for code that sends them.
	Kind string `json:"kind"`

	// True if a message handler appears to validate event.origin.
	// It is always false for "postMessageSend".
	OriginChecked bool `json:"originChecked"`

	// The targetOrigin given to postMessage, e.g. "*". Only set for
	// "postMessageSend".
	TargetOrigin string `json:"targetOrigin,omitempty"`

	Severity Severity `json:"severity"`

	// Dangerous sinks (innerHTML, eval( etc) found in a message handler
	Sinks []string `json:"sinks,omitempty"`

	// 1-based line number of the registration or call
	Line int `json:"line"`

	// The source of the registration or call, truncated to about 500
	// characters. If a handler was passed by reference, e.g.
	// addEventListener("message", onMessage), and was found elsewhere
	// in the file, then its source follows on a new line.
	Source string `json:"source"`

	// the filename in which the match was found
	Filename string `json:"filename,omitempty"`
}

// GetMessageListeners finds the places where the JavaScript receives
// or sends cross-origin messages with the postMessage API:
//
//	window.addEventListener("message", handler)  // addEventListener
//	$(window).on("message", handler)             // addEventListener
//	window.onmessage = handler                   // onmessage
//	otherWindow.postMessage(data, "*")           // postMessageSend
//
// A message handler that does not validate event.origin can be sent
// messages by any website, and if event.data then reaches a dangerous
// sink the result is often XSS. Receivers are therefore rated:
//
//	high    origin not checked, and the handler uses a dangerous sink
//	medium  origin not checked
//	low     origin checked
//
// Senders are rated medium when the targetOrigin is "*" (the data can be
// read by whichever page happens to be in the target window), and info
// otherwise.
//
// Handlers that are not written inline, e.g. addEventListener("message",
// onMessage), are followed to their definition if it is in the same file.
// Calls made by a handler are not followed, so a handler that hands the
// event to another function may have sinks and origin checks that are not
// reported. Matching is deliberately wide: any onmessage assignment or
// addEventListener("message") call is reported, which includes WebSockets,
// Workers, and MessagePorts that can not be reached cross-origin.
//
// When the input is HTML, line numbers are relative to the inline
// JavaScript extracted from it.
func (a *Analyzer) GetMessageListeners() []*MessageListener {
	out := make([]*MessageListener, 0)
	if a == nil || !a.rootNode.IsValid() {
		return out
	}

	idx := &pmIndex{root: a.rootNode}

	a.Query("[(call_expression) (assignment_expression)] @matches", func(n *Node) {
		var l *MessageListener

		switch n.Type() {
		case "call_expression":
			l = pmMatchCall(n, idx)
		case "assignment_expression":
			l = pmMatchAssignment(n, idx)
		}

		if l != nil {
			out = append(out, l)
		}
	})

	return out
}

// pmMatchCall looks for message listeners and senders that are
// registered by a function call.
func pmMatchCall(n *Node, idx *pmIndex) *MessageListener {
	name, obj := pmCallee(n.ChildByFieldName("function"))

	switch name {
	case "addEventListener":
		args := pmArgs(n)
		if len(args) < 2 {
			return nil
		}
		if ev, ok := pmStringValue(args[0]); !ok || ev != "message" {
			return nil
		}
		return pmReceiver(pmKindAddEventListener, n, args[1], idx)

	case "on", "bind", "one":
		// jQuery: $(window).on("message", handler). Only the window
		// is of interest; plenty of other things have an on() method.
		if !pmIsJQueryWindow(obj) {
			return nil
		}
		args := pmArgs(n)
		if len(args) < 2 {
			return nil
		}
		if ev, ok := pmStringValue(args[0]); !ok || !pmIsMessageEvent(ev) {
			return nil
		}
		return pmReceiver(pmKindAddEventListener, n, args[1], idx)

	case "postMessage":
		return pmSender(n, pmArgs(n))
	}

	return nil
}

// pmMatchAssignment looks for message handlers that are assigned to
// an onmessage property.
func pmMatchAssignment(n *Node, idx *pmIndex) *MessageListener {
	left := n.ChildByFieldName("left")

	name := ""
	switch pmType(left) {
	case "identifier":
		name = left.Content()
	case "member_expression":
		name = pmContent(left.ChildByFieldName("property"))
	case "subscript_expression":
		name, _ = pmStringValue(left.ChildByFieldName("index"))
	}
	if name != "onmessage" {
		return nil
	}

	// a.onmessage = b.onmessage = handler
	handler := pmUnchain(n.ChildByFieldName("right"))
	if !handler.IsValid() || pmIsNullish(handler) {
		// onmessage = null removes a handler rather than adding one
		return nil
	}

	return pmReceiver(pmKindOnMessage, n, handler, idx)
}

// pmSender returns a MessageListener for a postMessage call with
// a string targetOrigin, either as postMessage(data, "*") or
// postMessage(data, {targetOrigin: "*"}).
func pmSender(call *Node, args []*Node) *MessageListener {
	if len(args) < 2 {
		return nil
	}

	origin, ok := pmStringValue(args[1])
	if !ok && pmType(args[1]) == "object" {
		if v := args[1].AsObject().GetNode("targetOrigin"); v.IsValid() {
			origin, ok = pmStringValue(v)
		}
	}
	if !ok {
		// Worker.postMessage(data, [transferables]) and friends
		// have no targetOrigin, so there is nothing to report.
		return nil
	}

	sev := SeverityInfo
	if origin == "*" {
		sev = SeverityMedium
	}

	return &MessageListener{
		Kind:         pmKindSend,
		TargetOrigin: origin,
		Severity:     sev,
		Line:         pmLine(call),
		Source:       pmTruncate(call.Content(), pmMaxSource),
	}
}

// pmReceiver builds the MessageListener for a message handler that is
// registered at site. The handler is what was passed to be the handler,
// which is a function or maybe only a reference to one.
func pmReceiver(kind string, site, handler *Node, idx *pmIndex) *MessageListener {
	idx.steps = 0

	// fn is the function that handles the messages, or nil if it
	// can't be found. The origin can only be checked if it is found.
	fn := idx.resolve(handler, 0)

	// What the handler does can still be seen in the source of the
	// handler argument if it contains code, e.g. debounce(makeHandler(...))
	analyzed := fn
	if analyzed == nil {
		analyzed = handler
	}

	checked := pmOriginChecked(fn)
	sinks := pmSinks(analyzed)

	sev := SeverityLow
	switch {
	case !checked && pmHasDangerousSink(sinks):
		sev = SeverityHigh
	case !checked:
		sev = SeverityMedium
	}

	return &MessageListener{
		Kind:          kind,
		OriginChecked: checked,
		Severity:      sev,
		Sinks:         sinks,
		Line:          pmLine(site),
		Source:        pmSource(site, fn),
	}
}

// pmSource returns the source for a MessageListener. That is the source
// of the site where the handler is registered, followed by the source of
// the handler if it is defined somewhere else.
func pmSource(site, handler *Node) string {
	if !site.IsValid() {
		return ""
	}

	src := site.Content()
	if !handler.IsValid() || pmWithin(handler, site) {
		return pmTruncate(src, pmMaxSource)
	}

	return pmTruncate(pmTruncate(src, 160)+"\n"+handler.Content(), pmMaxSource)
}

// pmIsJQueryWindow returns true if n is a jQuery selection of the
// window, possibly with other methods chained on to it:
//
//	$(window)
//	jQuery(window).off("message")
func pmIsJQueryWindow(n *Node) bool {
	for i := 0; i < pmMaxHops && n.IsValid(); i++ {
		if n.Type() != "call_expression" {
			return false
		}

		fn := n.ChildByFieldName("function")
		switch pmType(fn) {
		case "member_expression":
			n = fn.ChildByFieldName("object")
		case "identifier":
			if c := fn.Content(); c != "$" && c != "jQuery" {
				return false
			}
			args := pmArgs(n)
			if len(args) == 0 {
				return false
			}
			switch args[0].Content() {
			case "window", "self", "top", "parent", "window.top", "window.parent", "window.self":
				return true
			}
			return false
		default:
			return false
		}
	}
	return false
}

// pmIsMessageEvent returns true if a jQuery event string includes
// the message event; e.g. "message", "message.myNamespace" or
// "resize message".
func pmIsMessageEvent(ev string) bool {
	for _, field := range strings.Fields(ev) {
		if strings.SplitN(field, ".", 2)[0] == "message" {
			return true
		}
	}
	return false
}

// pmIsNullish returns true for the values used to remove a handler
func pmIsNullish(n *Node) bool {
	switch pmType(n) {
	case "null", "undefined":
		return true
	case "identifier":
		return n.Content() == "undefined"
	case "unary_expression":
		return strings.HasPrefix(n.Content(), "void")
	}
	return false
}

// pmIndex is used to find the function that implements a message handler
// when the handler is not written inline. Finding the function matters
// because it is the function, and not the reference to it, that does
// or doesn't check the origin and does or doesn't use dangerous sinks.
type pmIndex struct {
	root *Node

	// The number of nodes looked at since resolving a handler began, so
	// that a pathological file can't make resolving one take forever.
	steps int

	// Things that are reachable by property name: methods, object
	// properties, class fields and assignments such as
	// this.onMessage = function(){}. Built the first time it's needed.
	members map[string][]*Node
}

// pmMaxSteps is how many nodes may be looked at to resolve one handler
const pmMaxSteps = 200

// resolve returns the function that is referred to by n; n itself if n
// is already a function. It returns nil if the function can't be found.
func (x *pmIndex) resolve(n *Node, hops int) *Node {
	x.steps++
	if !n.IsValid() || hops > pmMaxHops || x.steps > pmMaxSteps {
		return nil
	}

	t := n.Type()
	if pmIsFunction(t) {
		return n
	}

	switch t {
	case "parenthesized_expression":
		return x.resolve(n.NamedChild(0), hops+1)

	case "identifier":
		return x.resolve(pmLookupBinding(n), hops+1)

	case "member_expression":
		return x.resolveMember(n, hops+1)

	case "call_expression":
		// handler.bind(this)
		fn := n.ChildByFieldName("function")
		if pmType(fn) == "member_expression" && pmContent(fn.ChildByFieldName("property")) == "bind" {
			if found := x.resolve(fn.ChildByFieldName("object"), hops+1); found != nil {
				return found
			}
		}

		// Wrappers like debounce(handler, 100), _.bind(handler, this) or
		// once(function(e){...}). A message handler is given the event,
		// so a function with no parameters is more likely to be a callback
		// for something else: getHandler(config, function(){...})
		for _, arg := range pmArgs(n) {
			found := x.resolve(arg, hops+1)
			if found != nil && pmFirstParam(found).IsValid() {
				return found
			}
		}
	}

	return nil
}

// resolveMember finds the function that a member expression like
// this.onMessage or app.handlers.message refers to.
func (x *pmIndex) resolveMember(n *Node, hops int) *Node {
	prop := pmContent(n.ChildByFieldName("property"))
	if prop == "" {
		return nil
	}

	// this.method: the enclosing classes, constructors and objects
	// are the places to look, starting with the nearest one.
	if pmType(n.ChildByFieldName("object")) == "this" {
		for p := n.Parent(); p.IsValid(); p = p.Parent() {
			var candidates []*Node

			switch t := p.Type(); {
			case t == "class_body":
				candidates = append(pmMembersIn(p, prop), pmThisAssignments(p, prop)...)
			case t == "object":
				candidates = pmMembersIn(p, prop)
			case pmIsFunction(t) && t != "arrow_function":
				candidates = pmThisAssignments(p, prop)
			}

			for _, c := range candidates {
				if found := x.resolve(c, hops+1); found != nil {
					return found
				}
			}
		}
	}

	// Anything else: accept a function with that name if there's only one
	// of them in the file. A wrong guess is worse than no guess.
	var found *Node
	for _, c := range x.membersNamed(prop) {
		fn := x.resolve(c, hops+1)
		if fn == nil {
			continue
		}
		if found != nil && !pmSameNode(found, fn) {
			return nil
		}
		found = fn
	}

	return found
}

// membersNamed returns everything in the file that is defined as a
// property or method with the given name. That's the value that is
// given to the property, or the whole method.
func (x *pmIndex) membersNamed(name string) []*Node {
	if x.members == nil {
		x.members = make(map[string][]*Node)

		x.root.Query("[(method_definition) (pair) (public_field_definition) (assignment_expression)] @matches", func(n *Node) {
			var key string
			var value *Node

			switch n.Type() {
			case "method_definition":
				key, value = pmPropName(n.ChildByFieldName("name")), n
			case "pair":
				key, value = pmPropName(n.ChildByFieldName("key")), n.ChildByFieldName("value")
			case "public_field_definition":
				key, value = pmPropName(n.ChildByFieldName("property")), n.ChildByFieldName("value")
			case "assignment_expression":
				if left := n.ChildByFieldName("left"); pmType(left) == "member_expression" {
					key, value = pmContent(left.ChildByFieldName("property")), pmUnchain(n.ChildByFieldName("right"))
				}
			}

			if key != "" && pmIsReference(pmType(value)) {
				x.members[key] = append(x.members[key], value)
			}
		})
	}

	return x.members[name]
}

// pmIsReference returns true for the node types that can be a
// reference to a function, as well as a function itself.
func pmIsReference(nodeType string) bool {
	switch nodeType {
	case "identifier", "member_expression", "call_expression", "parenthesized_expression":
		return true
	}
	return pmIsFunction(nodeType)
}

// pmMembersIn finds the methods, fields and properties called name
// in the body of a class or in an object literal.
func pmMembersIn(container *Node, name string) []*Node {
	var out []*Node

	for _, m := range pmNamedChildren(container) {
		var key string
		var value *Node

		switch m.Type() {
		case "method_definition":
			key, value = pmPropName(m.ChildByFieldName("name")), m
		case "public_field_definition":
			key, value = pmPropName(m.ChildByFieldName("property")), m.ChildByFieldName("value")
		case "pair":
			key, value = pmPropName(m.ChildByFieldName("key")), m.ChildByFieldName("value")
		}

		if key == name && value.IsValid() {
			out = append(out, value)
		}
	}

	return out
}

// pmThisAssignments finds the values assigned to this.name
// somewhere inside scope, e.g. in a class's constructor:
//
//	this.handler = this.onMessage.bind(this);
func pmThisAssignments(scope *Node, name string) []*Node {
	var out []*Node

	scope.Query("(assignment_expression) @matches", func(n *Node) {
		left := n.ChildByFieldName("left")
		if pmType(left) != "member_expression" ||
			pmType(left.ChildByFieldName("object")) != "this" ||
			pmContent(left.ChildByFieldName("property")) != name {
			return
		}
		if v := pmUnchain(n.ChildByFieldName("right")); v.IsValid() {
			out = append(out, v)
		}
	})

	return out
}

// pmSameNode returns true if a and b are the same node in the tree
func pmSameNode(a, b *Node) bool {
	if !a.IsValid() || !b.IsValid() {
		return false
	}
	return a.node.StartByte() == b.node.StartByte() &&
		a.node.EndByte() == b.node.EndByte() &&
		a.node.Type() == b.node.Type()
}

// pmLookupBinding finds what an identifier is bound to by looking
// outwards through the scopes that enclose it. It returns nil if the
// identifier is a function parameter, or isn't defined in the file.
func pmLookupBinding(id *Node) *Node {
	name := pmContent(id)
	if name == "" {
		return nil
	}

	for cur := id; cur.IsValid(); {
		parent := cur.Parent()
		if !parent.IsValid() {
			break
		}

		switch t := parent.Type(); {
		case t == "statement_block" || t == "program":
			if value, declared := pmDeclaredIn(parent, name); declared {
				return value
			}
		case pmIsFunction(t):
			if pmParamNames(parent)[name] {
				return nil
			}
		}

		cur = parent
	}

	return nil
}

// pmDeclaredIn looks for a declaration of name in the statements of a
// block. It returns the value that name is bound to, if there is one,
// and whether name is declared in the block at all.
func pmDeclaredIn(block *Node, name string) (*Node, bool) {
	var value *Node
	declared := false

	stmts := pmNamedChildren(block)

	for _, stmt := range stmts {
		if pmType(stmt) == "export_statement" {
			if d := stmt.ChildByFieldName("declaration"); d.IsValid() {
				stmt = d
			}
		}

		switch pmType(stmt) {
		case "function_declaration", "generator_function_declaration":
			if pmContent(stmt.ChildByFieldName("name")) == name {
				return stmt, true
			}

		case "class_declaration":
			if pmContent(stmt.ChildByFieldName("name")) == name {
				declared = true
			}

		case "lexical_declaration", "variable_declaration":
			for _, d := range pmNamedChildren(stmt) {
				if pmType(d) != "variable_declarator" || pmContent(d.ChildByFieldName("name")) != name {
					continue
				}
				declared = true

				if v := d.ChildByFieldName("value"); value == nil && v.IsValid() {
					value = v
				}
			}
		}
	}

	if declared && value == nil {
		// declared here but assigned later: var h; h = function(e){...}
		for _, stmt := range stmts {
			if v := pmAssignedIn(stmt, name); v.IsValid() {
				return v, true
			}
		}
	}

	return value, declared
}

// pmAssignedIn finds a simple assignment to name in a statement:
//
//	name = value;
//	a = 1, name = value;
func pmAssignedIn(n *Node, name string) *Node {
	switch pmType(n) {
	case "expression_statement", "parenthesized_expression":
		return pmAssignedIn(n.NamedChild(0), name)

	case "sequence_expression":
		for _, c := range pmNamedChildren(n) {
			if v := pmAssignedIn(c, name); v.IsValid() {
				return v
			}
		}

	case "assignment_expression":
		left := n.ChildByFieldName("left")
		if pmType(left) == "identifier" && left.Content() == name {
			return pmUnchain(n.ChildByFieldName("right"))
		}
	}

	return nil
}

// pmParamNames returns the names bound by a function's parameters
func pmParamNames(fn *Node) map[string]bool {
	names := make(map[string]bool)

	var add func(p *Node)
	add = func(p *Node) {
		switch pmType(p) {
		case "identifier", "shorthand_property_identifier_pattern":
			names[p.Content()] = true
		case "assignment_pattern", "object_assignment_pattern":
			add(p.ChildByFieldName("left"))
		case "pair_pattern":
			add(p.ChildByFieldName("value"))
		case "formal_parameters", "rest_pattern", "object_pattern", "array_pattern":
			for _, c := range pmNamedChildren(p) {
				add(c)
			}
		}
	}

	add(fn.ChildByFieldName("parameter"))
	add(fn.ChildByFieldName("parameters"))

	return names
}

// pmFirstParam returns the first parameter of a function. That's the
// event, for a function that handles messages.
func pmFirstParam(fn *Node) *Node {
	if p := fn.ChildByFieldName("parameter"); p.IsValid() {
		return p
	}

	for _, p := range pmNamedChildren(fn.ChildByFieldName("parameters")) {
		if p.Type() != "comment" {
			return p
		}
	}

	return nil
}

// pmOriginCtx records which names in a message handler refer to the
// message event and to the origin of the event, so that the handler
// can be checked for tests of the origin.
type pmOriginCtx struct {
	// names that refer to the event: e, event, e.originalEvent etc
	events map[string]bool

	// names that refer to the origin: origin, o etc
	origins map[string]bool

	// the name of the event is unknown, so anything.origin is accepted
	anyObject bool
}

// pmCheckMethods are methods that are used to compare a string with
// something else, like a list of the origins that are allowed.
var pmCheckMethods = pmSet(
	"indexOf", "lastIndexOf", "includes", "startsWith", "endsWith",
	"test", "match", "matchAll", "search", "has", "get", "some",
	"every", "find", "findIndex", "localeCompare", "equals", "isEqual",
)

// pmCheckWords are words in the names of functions that check the
// origin that they are given: isAllowedOrigin(e.origin) and so on.
// The word origin is not one of them, because functions like
// postToOrigin(e.origin) and normalizeOrigin(e.origin) don't check anything.
var pmCheckWords = []string{
	"trust", "allow", "white", "black", "block", "deny",
	"valid", "verify", "check", "safe", "same", "match", "legit",
	"permit", "approv", "accept", "known", "expect", "secur", "auth",
	"equal", "hasown", "host", "domain", "cors",
}

// pmStrongCheckWords are words in the names of functions that are likely
// to check the origin of the event they're given: isTrusted(e) and so on.
// The list is shorter than pmCheckWords because validate(e) might be
// checking the message and not where it came from.
var pmStrongCheckWords = []string{
	"trust", "allow", "white", "verify", "authentic", "permit", "legit",
}

// pmOriginChecked returns true if a message handler appears to
// validate the origin of the message that it is given. An origin is
// validated if event.origin is compared with something, passed to a
// function that tests it, used to look something up, or switched on:
//
//	if (e.origin !== "https://example.com") return;
//	if (!allowed.includes(e.origin)) return;
//	if (!isTrustedOrigin(e.origin)) return;
//
// A handler that only mentions the origin, like console.log(e.origin),
// does not check it, and neither does comparing with e.data.origin
// because that's controlled by the sender of the message.
func pmOriginChecked(fn *Node) bool {
	if !fn.IsValid() || !pmIsFunction(fn.Type()) {
		return false
	}

	c := &pmOriginCtx{
		events:  make(map[string]bool),
		origins: make(map[string]bool),
	}
	c.bindParams(fn)

	// Find the aliases first: const {origin} = e; var o = e.origin;
	pmWalk(fn, func(n *Node) bool {
		switch n.Type() {
		case "variable_declarator":
			c.bindDeclarator(n)
		case "assignment_expression":
			if left := n.ChildByFieldName("left"); pmType(left) == "identifier" {
				c.bindName(left.Content(), n.ChildByFieldName("right"))
			}
		}
		return true
	})

	checked := false
	pmWalk(fn, func(n *Node) bool {
		if checked {
			return false
		}
		if c.isCheck(n) {
			checked = true
			return false
		}
		return true
	})

	return checked
}

// bindParams records the names for the event that come from the
// first parameter of the handler.
func (c *pmOriginCtx) bindParams(fn *Node) {
	p := pmFirstParam(fn)

	if pmType(p) == "assignment_pattern" {
		// function(e = {}){...}
		p = p.ChildByFieldName("left")
	}

	switch pmType(p) {
	case "identifier":
		c.events[p.Content()] = true
	case "object_pattern":
		// function({origin, data}){...}
		c.bindPattern(p)
	default:
		c.anyObject = true
	}
}

// bindDeclarator records the names that come from a declaration:
//
//	var e = event.originalEvent || event;
//	const {origin, data} = e;
//	let o = e.origin;
func (c *pmOriginCtx) bindDeclarator(n *Node) {
	name := n.ChildByFieldName("name")
	value := n.ChildByFieldName("value")

	switch pmType(name) {
	case "identifier":
		c.bindName(name.Content(), value)
	case "object_pattern":
		if c.isEvent(value) {
			c.bindPattern(name)
		}
	}
}

// bindName records a name that is assigned an event, or something
// derived from the origin of the event.
func (c *pmOriginCtx) bindName(name string, value *Node) {
	switch {
	case !value.IsValid():
	case c.isEvent(value):
		c.events[name] = true
	case c.contains(value):
		c.origins[name] = true
	}
}

// bindPattern records the names that the origin is given in a
// destructuring pattern: {origin}, {origin: o}, {origin = ""}
func (c *pmOriginCtx) bindPattern(pattern *Node) {
	for _, m := range pmNamedChildren(pattern) {
		switch m.Type() {
		case "shorthand_property_identifier_pattern":
			if m.Content() == "origin" {
				c.origins["origin"] = true
			}

		case "object_assignment_pattern":
			if pmContent(m.ChildByFieldName("left")) == "origin" {
				c.origins["origin"] = true
			}

		case "pair_pattern":
			if pmPropName(m.ChildByFieldName("key")) != "origin" {
				continue
			}
			v := m.ChildByFieldName("value")
			if pmType(v) == "assignment_pattern" {
				v = v.ChildByFieldName("left")
			}
			if pmType(v) == "identifier" {
				c.origins[v.Content()] = true
			}
		}
	}
}

// isEvent returns true if n is the message event: e, event.originalEvent
// (jQuery wraps the event), or (e.originalEvent || e).
func (c *pmOriginCtx) isEvent(n *Node) bool {
	switch pmType(n) {
	case "identifier":
		return c.events[n.Content()]

	case "parenthesized_expression":
		return c.isEvent(n.NamedChild(0))

	case "member_expression":
		return pmContent(n.ChildByFieldName("property")) == "originalEvent" &&
			c.isEvent(n.ChildByFieldName("object"))

	case "binary_expression":
		if op := pmContent(n.ChildByFieldName("operator")); op == "||" || op == "??" {
			return c.isEvent(n.ChildByFieldName("left")) && c.isEvent(n.ChildByFieldName("right"))
		}
	}
	return false
}

// isOrigin returns true if n is the origin of the message event,
// either directly (e.origin) or through a name that was bound to it.
func (c *pmOriginCtx) isOrigin(n *Node) bool {
	switch pmType(n) {
	case "identifier":
		return c.origins[n.Content()]

	case "parenthesized_expression":
		return c.isOrigin(n.NamedChild(0))

	case "member_expression":
		return pmContent(n.ChildByFieldName("property")) == "origin" &&
			c.isEventObject(n.ChildByFieldName("object"))

	case "subscript_expression":
		index, ok := pmStringValue(n.ChildByFieldName("index"))
		return ok && index == "origin" && c.isEventObject(n.ChildByFieldName("object"))

	case "binary_expression":
		// e.origin || e.originalEvent.origin
		switch pmContent(n.ChildByFieldName("operator")) {
		case "||", "??", "&&":
			return c.isOrigin(n.ChildByFieldName("left")) || c.isOrigin(n.ChildByFieldName("right"))
		}
	}
	return false
}

// isEventObject returns true if n is something that has the origin of
// a message as its origin property. That is the event, unless the name
// of the event isn't known, when it's anything except the window and
// location objects, whose origin is the origin of the page itself.
func (c *pmOriginCtx) isEventObject(n *Node) bool {
	if c.isEvent(n) {
		return true
	}
	if !c.anyObject {
		return false
	}

	switch strings.ReplaceAll(pmContent(n), "?.", ".") {
	case "window", "self", "top", "parent", "globalThis", "document", "location", "this":
		return false
	}
	return !strings.HasSuffix(pmContent(n), "location")
}

// contains returns true if n is, or contains, the origin of the event
func (c *pmOriginCtx) contains(n *Node) bool {
	found := false

	pmWalk(n, func(x *Node) bool {
		if found {
			return false
		}
		if c.isOrigin(x) {
			found = true
			return false
		}
		return true
	})

	return found
}

// isCheck returns true if n tests the origin of the event
func (c *pmOriginCtx) isCheck(n *Node) bool {
	switch n.Type() {
	case "binary_expression":
		switch pmContent(n.ChildByFieldName("operator")) {
		case "==", "===", "!=", "!==", "in":
			return c.contains(n.ChildByFieldName("left")) || c.contains(n.ChildByFieldName("right"))
		}

	case "switch_statement":
		return c.contains(n.ChildByFieldName("value"))

	case "subscript_expression":
		// allowed[e.origin]
		return c.contains(n.ChildByFieldName("index"))

	case "call_expression":
		return c.isCheckCall(n)
	}

	return false
}

// isCheckCall returns true if a function call tests the origin of the event
func (c *pmOriginCtx) isCheckCall(call *Node) bool {
	fn := call.ChildByFieldName("function")
	name, obj := pmCallee(fn)
	args := pmArgs(call)

	anyArg := func(test func(*Node) bool) bool {
		for _, arg := range args {
			if test(arg) {
				return true
			}
		}
		return false
	}

	// allowed.includes(e.origin), e.origin.endsWith(".example.com"),
	// /^https:\/\/example\.com$/.test(e.origin) and so on
	if pmCheckMethods[name] && (c.contains(obj) || anyArg(c.contains)) {
		return true
	}

	switch pmType(fn) {
	case "identifier", "member_expression", "subscript_expression":
		callee := strings.ToLower(fn.Content())
		weak := pmContainsAny(callee, pmCheckWords)

		// isAllowedOrigin(e.origin)
		if weak && anyArg(c.contains) {
			return true
		}

		// isTrusted(e), checkOrigin(e). The origin is only a clue when it comes
		// with a word for checking: getOrigin(e) and postToOrigin(e) check nothing.
		strong := pmContainsAny(callee, pmStrongCheckWords) || (weak && strings.Contains(callee, "origin"))
		if strong && anyArg(c.isEvent) {
			return true
		}
	}

	return false
}

// pmSinkMarker is something that is dangerous to find in
// a message handler, and a way to find it.
type pmSinkMarker struct {
	name  string
	match func(src string) bool
}

// pmSinkMarkers lists the dangerous things to look for in a message
// handler. The names are the strings that appear in Sinks.
var pmSinkMarkers = []pmSinkMarker{
	{"innerHTML", pmContains("innerHTML")},
	{"outerHTML", pmContains("outerHTML")},
	{"document.write", pmMatches(`document\s*\.\s*write`)},
	{"insertAdjacentHTML", pmContains("insertAdjacentHTML")},
	{"eval(", pmMatches(`(?:^|[^\w$])eval\s*\(`)},
	{"new Function", pmMatches(`new\s+Function\b`)},
	{"Function(", pmMatches(`(?:^|[^\w$])Function\s*\(`)},
	{"setTimeout", pmHasTimeoutSink},

	// Assigning to location or calling location.assign etc.
	// Reading location.origin and so on is harmless.
	{"location", pmMatches(
		`(?:^|[^\w$])location(?:\s*\.\s*href)?\s*[-+*/%&|^]?=(?:[^=>]|$)` +
			`|(?:^|[^\w$])location\s*\.\s*(?:assign|replace)\s*\(`,
	)},

	{".src", pmMatches(`\.src\b`)},

	// jQuery's html(value) sets HTML, but html() reads it
	{".html(", pmMatches(`\.html\s*\(\s*[^)\s]`)},

	{"document.cookie", pmMatches(`document\s*\.\s*cookie`)},
	{"dangerouslySetInnerHTML", pmContains("dangerouslySetInnerHTML")},
	{".postMessage", pmMatches(`\.postMessage\b`)},
}

var (
	pmReTimeoutCall = regexp.MustCompile(`(?:^|[^\w$])setTimeout\s*\(`)

	// the start of the arguments to a call where the first argument
	// is a function, or a name that's probably a function. Minifiers
	// wrap function expressions in parentheses: setTimeout((function(){...}),1e3)
	pmReCallbackArg = regexp.MustCompile(
		`^\s*\(*\s*(?:async\b|function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*(?:=>|[,)]))`,
	)
)

// pmHasTimeoutSink returns true if src calls setTimeout in a way
// that can evaluate a string. setTimeout(function(){...}, 100) is
// harmless but setTimeout(e.data, 100) is eval in disguise.
func pmHasTimeoutSink(src string) bool {
	for _, loc := range pmReTimeoutCall.FindAllStringIndex(src, -1) {
		if !pmReCallbackArg.MatchString(src[loc[1]:]) {
			return true
		}
	}
	return false
}

// pmHasDangerousSink reports whether sinks contains a code-execution, HTML, or
// navigation sink: i.e. any sink other than a ".postMessage" reply. Replying to
// the sender via postMessage is worth surfacing, but on its own it is extremely
// common in Worker/MessagePort boilerplate, so it only contributes to a high
// severity rating when a genuinely dangerous sink is present alongside it.
func pmHasDangerousSink(sinks []string) bool {
	for _, s := range sinks {
		if s != ".postMessage" {
			return true
		}
	}
	return false
}

// pmSinks returns the names of the dangerous sinks found in the
// source of a message handler.
func pmSinks(handler *Node) []string {
	if !handler.IsValid() {
		return nil
	}
	src := handler.Content()

	var out []string
	sawNewFunction := false

	for _, m := range pmSinkMarkers {
		if !m.match(src) {
			continue
		}

		// new Function( always contains Function(
		if m.name == "new Function" {
			sawNewFunction = true
		}
		if m.name == "Function(" && sawNewFunction {
			continue
		}

		out = append(out, m.name)
	}

	return out
}

// pmContains returns a function that tests for a substring
func pmContains(substr string) func(string) bool {
	return func(s string) bool {
		return strings.Contains(s, substr)
	}
}

// pmMatches returns a function that tests for a regular expression
func pmMatches(expr string) func(string) bool {
	return regexp.MustCompile(expr).MatchString
}

// pmContainsAny returns true if s contains any of the substrings
func pmContainsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// pmSet returns a set of the provided strings
func pmSet(items ...string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

// pmIsFunction returns true for the node types that are functions
func pmIsFunction(nodeType string) bool {
	switch nodeType {
	case "function", "function_expression", "arrow_function", "generator_function",
		"function_declaration", "generator_function_declaration", "method_definition":
		return true
	}
	return false
}

// pmType is like Node.Type, but safe to call on a nil *Node
func pmType(n *Node) string {
	if !n.IsValid() {
		return ""
	}
	return n.Type()
}

// pmContent is like Node.Content, but safe to call on a nil *Node
func pmContent(n *Node) string {
	if !n.IsValid() {
		return ""
	}
	return n.Content()
}

// pmLine returns the 1-based line number on which a node starts
func pmLine(n *Node) int {
	if !n.IsValid() {
		return 0
	}
	return int(n.node.StartPoint().Row) + 1
}

// pmWithin returns true if inner is part of the source of outer
func pmWithin(inner, outer *Node) bool {
	if !inner.IsValid() || !outer.IsValid() {
		return false
	}
	return inner.node.StartByte() >= outer.node.StartByte() &&
		inner.node.EndByte() <= outer.node.EndByte()
}

// pmTruncate shortens s to about limit bytes, without splitting a rune
func pmTruncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// pmStringValue returns the value of a string literal, or of a template
// literal with nothing interpolated into it.
func pmStringValue(n *Node) (string, bool) {
	switch pmType(n) {
	case "string":
		return n.DecodedString(), true
	case "template_string":
		if c := n.Content(); !strings.Contains(c, "${") {
			return DecodeString(c), true
		}
	}
	return "", false
}

// pmPropName returns the name of a property, method or field
func pmPropName(n *Node) string {
	switch pmType(n) {
	case "property_identifier", "private_property_identifier", "identifier", "shorthand_property_identifier":
		return n.Content()
	case "string":
		return n.DecodedString()
	}
	return ""
}

// pmCallee returns the name of the function being called, and
// for method calls the object that the method is called on.
//
//	foo(a)    -> foo, nil
//	x.foo(a)  -> foo, x
//	x["foo"]  -> foo, x
func pmCallee(fn *Node) (string, *Node) {
	switch pmType(fn) {
	case "identifier":
		return fn.Content(), nil

	case "member_expression":
		return pmContent(fn.ChildByFieldName("property")), fn.ChildByFieldName("object")

	case "subscript_expression":
		if name, ok := pmStringValue(fn.ChildByFieldName("index")); ok {
			return name, fn.ChildByFieldName("object")
		}
	}
	return "", nil
}

// pmArgs returns the arguments to a function call, without comments
func pmArgs(call *Node) []*Node {
	args := call.ChildByFieldName("arguments")
	if pmType(args) != "arguments" {
		// tagged templates have no arguments node
		return nil
	}

	out := make([]*Node, 0)
	for _, arg := range pmNamedChildren(args) {
		if arg.Type() != "comment" {
			out = append(out, arg)
		}
	}
	return out
}

// pmUnchain returns the value at the end of a chain of assignments;
// the handler in a.onmessage = b.onmessage = handler
func pmUnchain(n *Node) *Node {
	for i := 0; i < pmMaxHops && pmType(n) == "assignment_expression"; i++ {
		n = n.ChildByFieldName("right")
	}
	return n
}

// pmNamedChildren returns the named children of a node. Node.NamedChildren
// is slow for nodes with many children, e.g. the program node of a big
// file, because finding the nth child means counting from the first.
func pmNamedChildren(n *Node) []*Node {
	out := make([]*Node, 0)
	if !n.IsValid() {
		return out
	}

	c := sitter.NewTreeCursor(n.node)
	defer c.Close()

	if !c.GoToFirstChild() {
		return out
	}

	for {
		if child := c.CurrentNode(); child != nil && child.IsNamed() {
			out = append(out, NewNode(child, n.source))
		}
		if !c.GoToNextSibling() {
			break
		}
	}

	return out
}

// pmWalk calls fn for a node, and then for each of its named
// descendants in the order they appear in the source. The children
// of a node are skipped if fn returns false for the node.
func pmWalk(n *Node, fn func(*Node) bool) {
	if !n.IsValid() || !fn(n) {
		return
	}

	for _, child := range pmNamedChildren(n) {
		pmWalk(child, fn)
	}
}
