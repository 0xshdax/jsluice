package jsluice

import (
	"strconv"
	"strings"
	"unicode/utf8"

	sitter "github.com/smacker/go-tree-sitter"
)

// A Sink is a place in the JavaScript source where a value is handed to
// something that can lead to DOM-based XSS or other client-side code
// execution: an innerHTML assignment, document.write, eval, jQuery's
// .html(), React's dangerouslySetInnerHTML and so on.
//
// Tainted is a cheap heuristic and not proof of exploitability. It is true
// when the value that reaches the sink contains a well-known attacker
// controllable source (location.hash, document.referrer, window.name etc).
// There is no data-flow analysis, so a value that is first stored in a
// variable will not be flagged: a sink that is not Tainted is not safe,
// it just means that no source was visible at the sink itself.
type Sink struct {
	// The type of sink; e.g. innerHTML, documentWrite, eval
	Kind string `json:"kind"`

	// High for tainted HTML/code execution sinks; see GetSinks
	Severity Severity `json:"severity"`

	// True if the value reaching the sink contains a known source
	Tainted bool `json:"tainted"`

	// The source that was found, e.g. location.hash
	Taint string `json:"taint,omitempty"`

	// The 1-based line number of the sink
	Line int `json:"line"`

	// The source code of the sink, truncated to roughly 400 characters
	Source string `json:"source"`

	// The filename in which the sink was found
	Filename string `json:"filename,omitempty"`
}

// The kinds of sink that GetSinks reports
const (
	sinkKindInnerHTML               = "innerHTML"
	sinkKindOuterHTML               = "outerHTML"
	sinkKindSrc                     = "src"
	sinkKindSrcdoc                  = "srcdoc"
	sinkKindHref                    = "href"
	sinkKindDocumentCookie          = "documentCookie"
	sinkKindDocumentWrite           = "documentWrite"
	sinkKindInsertAdjacentHTML      = "insertAdjacentHTML"
	sinkKindJQueryHTML              = "jQueryHtml"
	sinkKindJQueryManip             = "jQueryManip"
	sinkKindSetAttribute            = "setAttribute"
	sinkKindEval                    = "eval"
	sinkKindSetTimeoutString        = "setTimeoutString"
	sinkKindSetIntervalString       = "setIntervalString"
	sinkKindFunction                = "Function"
	sinkKindDOMParser               = "DOMParser"
	sinkKindDangerouslySetInnerHTML = "dangerouslySetInnerHTML"
)

// sinkMaxSource is the maximum length, in bytes, of Sink.Source
const sinkMaxSource = 400

// sinkTaintSources are the substrings that suggest a value is controlled
// by an attacker. They are ordered most-specific first; a bare 'location'
// or '.hash' is a weaker signal than 'location.hash', but still useful.
var sinkTaintSources = []string{
	"location.hash",
	"location.search",
	"location.href",
	"location.pathname",
	"location",
	"document.URL",
	"document.documentURI",
	"document.referrer",
	"document.cookie",
	"window.name",
	"URLSearchParams",
	"decodeURIComponent",
	"unescape",
	"atob",
	".hash",
	".search",
	".searchParams",
}

// sinkSetAttributeNames are the attributes that setAttribute can use
// to navigate, load content, or run script. Any on* event handler
// attribute is also considered; see sinkIsDangerousAttribute.
var sinkSetAttributeNames = newSet([]string{
	"href", "src", "srcdoc", "action", "formaction",
	"onload", "onerror", "data", "xlink:href",
})

// sinkGlobalObjects are the objects that eval, setTimeout etc
// can be called on without changing what they do
var sinkGlobalObjects = newSet([]string{
	"window", "self", "globalThis", "top", "parent", "frames",
})

// GetSinks searches the JavaScript source code for DOM-XSS sinks: places
// where a value is written to something that parses it as HTML, loads it as
// a URL, or runs it as code. The kinds of sink it reports are:
//
//	innerHTML, outerHTML,    assignments to those properties, including +=
//	src, srcdoc, href
//	documentCookie           assignments to document.cookie
//	documentWrite            document.write() and document.writeln()
//	insertAdjacentHTML       .insertAdjacentHTML()
//	jQueryHtml               .html(content)
//	jQueryManip              .append(), .prepend(), .after(), .before(),
//	                         .replaceWith() and .wrap()
//	setAttribute             .setAttribute() of href, src, srcdoc, action,
//	                         formaction, data, xlink:href or an on* handler
//	eval, Function           eval(), new Function() and Function()
//	setTimeoutString,        setTimeout() and setInterval() called with a
//	setIntervalString        string rather than a function
//	DOMParser                .parseFromString(markup, "text/html")
//	dangerouslySetInnerHTML  React's property, in an object or in JSX
//
// Severity is High for tainted and Medium for untainted HTML and code
// execution sinks (innerHTML, outerHTML, documentWrite, insertAdjacentHTML,
// jQueryHtml, dangerouslySetInnerHTML, eval, Function, setTimeoutString
// and setIntervalString). For all other sinks it is Medium for tainted
// and Low for untainted.
//
// A Sink is Tainted when the value that reaches it contains a source of
// attacker-controlled data such as location.hash or document.referrer, and
// Taint says which source it was. Only code counts: a source mentioned in a
// string, a comment or a regular expression is ignored. There is no data-flow
// analysis, so a value that has been put in a variable on the way is not
// seen. Tainted is somewhere to start looking, not proof of anything.
//
// Things that look like sinks, but can't be one, are left out to keep the
// noise down: assigning an empty string, calls without arguments, name/value
// calls like FormData.append(name, value), callbacks passed to .before() and
// friends, setTimeout() with a function, and write() on things that don't look
// like document.
//
// The results are in the order they appear in the source and are de-duplicated
// on kind, line and source. Handling of postMessage is not part of GetSinks.
func (a *Analyzer) GetSinks() []*Sink {
	out := make([]*Sink, 0)
	seen := make(map[string]struct{})
	mask := &sinkMask{}

	enter := func(n *Node) {
		var kind string
		var values []*Node

		switch n.Type() {
		case "assignment_expression", "augmented_assignment_expression":
			kind, values = sinkFromAssignment(n)
		case "call_expression":
			kind, values = sinkFromCall(n)
		case "new_expression":
			kind, values = sinkFromNew(n)
		case "pair":
			kind, values = sinkFromPair(n)
		case "jsx_attribute":
			kind, values = sinkFromJSXAttribute(n)
		}

		if kind == "" {
			return
		}

		tainted, taint := sinkTaintNodes(mask, values...)

		sink := &Sink{
			Kind:     kind,
			Severity: sinkSeverity(kind, tainted),
			Tainted:  tainted,
			Taint:    taint,
			Line:     int(n.node.StartPoint().Row) + 1,
			Source:   sinkSource(n),
		}

		// the same sink can be reached more than once, so de-duplicate
		key := sink.Kind + "\x00" + strconv.Itoa(sink.Line) + "\x00" + sink.Source
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}

		out = append(out, sink)
	}

	a.Query(`[
		(assignment_expression)
		(augmented_assignment_expression)
		(call_expression)
		(new_expression)
		(pair)
		(jsx_attribute)
	] @sinks`, enter)

	return out
}

// sinkSeverity returns the Severity for a kind of sink. HTML and code
// execution sinks are one step more serious than the other sinks.
func sinkSeverity(kind string, tainted bool) Severity {
	switch kind {
	case sinkKindInnerHTML,
		sinkKindOuterHTML,
		sinkKindDocumentWrite,
		sinkKindInsertAdjacentHTML,
		sinkKindJQueryHTML,
		sinkKindDangerouslySetInnerHTML,
		sinkKindEval,
		sinkKindFunction,
		sinkKindSetTimeoutString,
		sinkKindSetIntervalString:
		if tainted {
			return SeverityHigh
		}
		return SeverityMedium
	default:
		if tainted {
			return SeverityMedium
		}
		return SeverityLow
	}
}

// sinkTaint reports whether the source code for a node contains a known
// source of attacker-controlled data, and returns the first source found.
// Sources are matched in the order they appear in sinkTaintSources, so a
// more specific source (location.hash) wins over a less specific one
// (location). Matches must not be part of a longer identifier, so
// 'geolocation' and '.hashCode' are not sources, and nor is anything that
// is only mentioned in a string or a comment; see sinkMask.
func sinkTaint(n *Node) (bool, string) {
	return sinkTaintNodes(nil, n)
}

// sinkTaintNodes is like sinkTaint, but for the combined content of
// several nodes; e.g. all of the arguments to a function call. The
// mask is optional and only makes things faster.
func sinkTaintNodes(mask *sinkMask, nodes ...*Node) (bool, string) {
	raw := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.IsValid() {
			raw = append(raw, n.Content())
		}
	}

	// Almost every value has nothing in it that looks like a source, so
	// find that out before doing the work of picking out the code
	if _, found := sinkFirstSource(raw); !found {
		return false, ""
	}

	// Place names in UI text and keys like 'kismet.common.location.alt'
	// are not sources, so look again at just the code
	code := make([]string, 0, len(raw))
	for _, n := range nodes {
		if n.IsValid() {
			code = append(code, mask.codeFor(n))
		}
	}

	source, found := sinkFirstSource(code)
	return found, source
}

// sinkFirstSource returns the first of sinkTaintSources found in any of the
// provided strings.
func sinkFirstSource(contents []string) (string, bool) {
	for _, source := range sinkTaintSources {
		for _, c := range contents {
			if sinkHasSource(c, source) {
				return source, true
			}
		}
	}
	return "", false
}

// A sinkMask works out the code in a node: its source code with everything
// that isn't code blanked out with spaces. That is the text of strings and
// template literals, regular expressions, comments and JSX text. Everything
// else stays exactly where it was, so a source in the ${...} of a template
// literal is still found.
//
// It remembers the latest region of the source it has worked out. Sinks are
// found outermost first, so those nested inside another sink can use the code
// of the outer one instead of starting over, which would take quadratic time
// for sinks nested deeply. A nil *sinkMask works; it just remembers nothing.
type sinkMask struct {
	start int
	end   int
	code  []byte
}

// codeFor returns the code for a node.
func (m *sinkMask) codeFor(n *Node) string {
	start, end := int(n.node.StartByte()), int(n.node.EndByte())
	if start < 0 || start > end || end > len(n.source) {
		return ""
	}

	if m != nil && m.code != nil && start >= m.start && end <= m.end {
		return string(m.code[start-m.start : end-m.start])
	}

	code := make([]byte, end-start)
	copy(code, n.source[start:end])
	sinkBlank(n.node, n.source, code, start)

	if m != nil {
		m.start, m.end, m.code = start, end, code
	}
	return string(code)
}

// sinkBlank blanks the parts of buf that aren't code, for the tree below
// root. The buf holds a copy of the source, which starts at the offset base.
func sinkBlank(root *sitter.Node, source []byte, buf []byte, base int) {
	c := sitter.NewTreeCursor(root)
	defer c.Close()

	// This walks the tree with a cursor instead of recursing, so that
	// very deeply nested code can't use up the stack
	recurse := true
	for {
		if recurse {
			node := c.CurrentNode()
			start, end := int(node.StartByte()), int(node.EndByte())

			switch node.Type() {
			case "string", "regex", "comment", "jsx_text":
				sinkBlankRange(buf, start-base, end-base)
				recurse = false

			case "template_string":
				// The text in a template literal isn't a node of its own, so blank
				// all of it and then put the substitutions, which are code, back
				sinkBlankRange(buf, start-base, end-base)

			case "template_substitution":
				if start >= base && start-base < len(buf) && end <= len(source) {
					copy(buf[start-base:], source[start:end])
				}
			}
		}

		if recurse && c.GoToFirstChild() {
			continue
		}
		if c.GoToNextSibling() {
			recurse = true
			continue
		}
		if c.GoToParent() {
			recurse = false
			continue
		}
		break
	}
}

// sinkBlankRange replaces buf[from:to] with spaces, within bounds.
func sinkBlankRange(buf []byte, from, to int) {
	if from < 0 {
		from = 0
	}
	if to > len(buf) {
		to = len(buf)
	}
	for i := from; i < to; i++ {
		buf[i] = ' '
	}
}

// sinkHead returns the first part of the source code for a node, with no
// more than limit bytes.
func sinkHead(n *Node, limit int) string {
	if !n.IsValid() {
		return ""
	}

	start, end := int(n.node.StartByte()), int(n.node.EndByte())
	if start < 0 || start > end || end > len(n.source) {
		return ""
	}
	if end-start > limit {
		end = start + limit
	}
	return string(n.source[start:end])
}

// sinkHasSource returns true if source appears in content other than as
// part of a longer identifier. Sources that start with a '.' have to be a
// property access, so they must directly follow an identifier, a call or an
// index; that rules out the likes of $(".search-box").
func sinkHasSource(content, source string) bool {
	for from := 0; from < len(content); {
		i := strings.Index(content[from:], source)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(source)

		var leftOK bool
		switch {
		case i == 0:
			leftOK = source[0] != '.'
		case source[0] == '.':
			prev := content[i-1]
			leftOK = sinkIsIdentByte(prev) || prev == ')' || prev == ']'
		default:
			leftOK = !sinkIsIdentByte(content[i-1])
		}

		rightOK := end >= len(content) || !sinkIsIdentByte(content[end])
		if leftOK && rightOK {
			return true
		}

		from = i + 1
	}
	return false
}

// sinkIsIdentByte returns true for bytes that can be part of a JavaScript
// identifier. Any non-ASCII byte is assumed to be part of an identifier.
func sinkIsIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 0x80 ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// sinkSource returns the source code of a node, truncated to roughly
// sinkMaxSource bytes. It works on the byte offsets rather than calling
// Content() so that a huge node does not have to be copied just to
// throw most of it away.
func sinkSource(n *Node) string {
	start, end := int(n.node.StartByte()), int(n.node.EndByte())
	if start < 0 || start > end || end > len(n.source) {
		return ""
	}

	if end-start <= sinkMaxSource {
		return string(n.source[start:end])
	}

	// make room for the ellipsis, and don't cut a multi-byte character in half
	cut := start + sinkMaxSource - 3
	for cut > start && !utf8.RuneStart(n.source[cut]) {
		cut--
	}
	return string(n.source[start:cut]) + "..."
}

// sinkFromAssignment inspects assignments (and augmented assignments
// like +=) for properties that are dangerous to write to.
func sinkFromAssignment(n *Node) (string, []*Node) {
	left := n.ChildByFieldName("left")
	right := n.ChildByFieldName("right")
	if !left.IsValid() || !right.IsValid() {
		return "", nil
	}

	// Only operators that can build up a string are interesting; -= and
	// friends can't write markup. An augmented_assignment_expression has
	// no field name for its operator, so look at the source between the
	// two operands instead.
	if n.Type() == "augmented_assignment_expression" {
		start, end := int(left.node.EndByte()), int(right.node.StartByte())
		if start < 0 || start > end || end > len(n.source) {
			return "", nil
		}

		switch strings.TrimSpace(string(n.source[start:end])) {
		case "+=", "||=", "&&=", "??=":
		default:
			return "", nil
		}
	}

	var kind string
	switch sinkPropName(left) {
	case "innerHTML":
		kind = sinkKindInnerHTML
	case "outerHTML":
		kind = sinkKindOuterHTML
	case "src":
		kind = sinkKindSrc
	case "srcdoc":
		kind = sinkKindSrcdoc
	case "href":
		kind = sinkKindHref
	case "cookie":
		if sinkIsDocument(left.ChildByFieldName("object")) {
			kind = sinkKindDocumentCookie
		}
	}
	if kind == "" {
		return "", nil
	}

	// el.innerHTML = '' is how you clear an element, and an empty
	// string can't carry anything an attacker controls
	if sinkIsEmptyString(right) {
		return "", nil
	}

	return kind, []*Node{right}
}

// sinkFromCall inspects function calls for the dangerous functions and methods.
func sinkFromCall(n *Node) (string, []*Node) {
	name, recv := sinkCallee(n.ChildByFieldName("function"))
	if name == "" {
		return "", nil
	}

	// a tagged template has a template_string where the arguments
	// would be, and that isn't a call to anything we're looking for
	argsNode := n.ChildByFieldName("arguments")
	if !argsNode.IsValid() || argsNode.Type() != "arguments" {
		return "", nil
	}

	args := sinkArgs(argsNode)
	if len(args) == 0 {
		return "", nil
	}

	// foo.bar() as opposed to foo()
	isMethod := recv.IsValid()

	// eval(), window.eval() and (0, eval)() are all the same function
	isGlobal := !isMethod || sinkIsGlobal(recv)

	switch name {
	case "write", "writeln":
		if isMethod && sinkIsDocumentWrite(recv, args) {
			return sinkKindDocumentWrite, args
		}

	case "insertAdjacentHTML":
		if isMethod {
			// the first argument is the position and not the HTML
			if len(args) > 1 {
				return sinkKindInsertAdjacentHTML, args[1:]
			}
			return sinkKindInsertAdjacentHTML, args
		}

	case "html":
		// $(el).html() with no arguments is the getter and has
		// already been excluded by the check on len(args)
		if isMethod {
			return sinkKindJQueryHTML, args
		}

	case "append", "prepend", "after", "before", "replaceWith", "wrap":
		if isMethod && !sinkIsNameValueCall(args) && !sinkAllFunctions(args) {
			return sinkKindJQueryManip, args
		}

	case "setAttribute":
		if isMethod && len(args) > 1 {
			attr, ok := sinkLiteral(args[0])
			if ok && sinkIsDangerousAttribute(attr) {
				return sinkKindSetAttribute, args[1:]
			}
		}

	case "parseFromString":
		if isMethod && len(args) > 1 {
			mime, ok := sinkLiteral(args[1])
			if ok && strings.EqualFold(strings.TrimSpace(mime), "text/html") {
				return sinkKindDOMParser, args[:1]
			}
		}

	case "eval":
		if isGlobal {
			return sinkKindEval, args[:1]
		}

	case "Function":
		// Function("return this") is the same as new Function(...)
		if isGlobal {
			return sinkKindFunction, args
		}

	case "setTimeout":
		if isGlobal && sinkIsStringy(args[0]) {
			return sinkKindSetTimeoutString, args[:1]
		}

	case "setInterval":
		if isGlobal && sinkIsStringy(args[0]) {
			return sinkKindSetIntervalString, args[:1]
		}
	}

	return "", nil
}

// sinkFromNew inspects new expressions for the Function constructor.
func sinkFromNew(n *Node) (string, []*Node) {
	name, recv := sinkCallee(n.ChildByFieldName("constructor"))
	if name != "Function" || (recv.IsValid() && !sinkIsGlobal(recv)) {
		return "", nil
	}

	argsNode := n.ChildByFieldName("arguments")
	if !argsNode.IsValid() || argsNode.Type() != "arguments" {
		return "", nil
	}

	args := sinkArgs(argsNode)
	if len(args) == 0 {
		return "", nil
	}

	return sinkKindFunction, args
}

// sinkFromPair inspects object properties for React's dangerouslySetInnerHTML,
// e.g. React.createElement("div", {dangerouslySetInnerHTML: {__html: data}})
func sinkFromPair(n *Node) (string, []*Node) {
	key := n.ChildByFieldName("key")
	if !key.IsValid() {
		return "", nil
	}

	var name string
	switch key.Type() {
	case "property_identifier":
		name = key.Content()
	case "string":
		name = key.RawString()
	}
	if name != "dangerouslySetInnerHTML" {
		return "", nil
	}

	value := n.ChildByFieldName("value")
	if !value.IsValid() {
		return "", nil
	}

	return sinkKindDangerouslySetInnerHTML, []*Node{sinkReactHTML(value)}
}

// sinkFromJSXAttribute inspects JSX attributes for React's dangerouslySetInnerHTML,
// e.g. <div dangerouslySetInnerHTML={{__html: data}} />
func sinkFromJSXAttribute(n *Node) (string, []*Node) {
	// the name and the value of a jsx_attribute have no field names
	name := n.NamedChild(0)
	if !name.IsValid() || name.Content() != "dangerouslySetInnerHTML" {
		return "", nil
	}

	value := n.NamedChild(1)
	if !value.IsValid() {
		return "", nil
	}

	// {{__html: data}} is a jsx_expression containing an object
	if value.Type() == "jsx_expression" {
		inner := value.NamedChild(0)
		if !inner.IsValid() {
			return "", nil
		}
		value = inner
	}

	return sinkKindDangerouslySetInnerHTML, []*Node{sinkReactHTML(value)}
}

// sinkReactHTML finds the __html value in the object that is the
// value of a dangerouslySetInnerHTML property. If the value is
// not an object literal (e.g. a function call that returns one) the
// value itself is returned.
func sinkReactHTML(value *Node) *Node {
	if value.Type() == "object" {
		if html := value.AsObject().GetNode("__html"); html.IsValid() {
			return html
		}
	}
	return value
}

// sinkPropName returns the name of the property accessed by a
// member_expression (a.b) or by a subscript_expression with a literal
// index (a['b']). It returns an empty string for anything else.
func sinkPropName(n *Node) string {
	if !n.IsValid() {
		return ""
	}

	switch n.Type() {
	case "member_expression":
		prop := n.ChildByFieldName("property")
		if prop.IsValid() {
			return prop.Content()
		}
	case "subscript_expression":
		name, _ := sinkLiteral(n.ChildByFieldName("index"))
		return name
	}
	return ""
}

// sinkCallee works out the name of the function being called or constructed
// from the 'function' (or 'constructor') field of a call_expression
// (or new_expression). For plain function calls like eval(x) only the name is
// returned, and for method calls like window.eval(x) the name is that of the
// method and recv is the node for the object it was called on.
func sinkCallee(fn *Node) (name string, recv *Node) {
	if !fn.IsValid() {
		return "", nil
	}

	switch fn.Type() {
	case "identifier":
		return fn.Content(), nil

	case "member_expression", "subscript_expression":
		obj := fn.ChildByFieldName("object")
		if !obj.IsValid() {
			return "", nil
		}
		return sinkPropName(fn), obj

	case "parenthesized_expression":
		// indirect calls like (0, eval)(x) or (window.eval)(x)
		inner := fn.NamedChild(0)
		if !inner.IsValid() {
			return "", nil
		}
		if inner.Type() == "sequence_expression" {
			return sinkCallee(inner.ChildByFieldName("right"))
		}
		return sinkCallee(inner)
	}

	return "", nil
}

// sinkArgs returns the arguments in an arguments node, leaving out
// any comments that appear between them.
func sinkArgs(args *Node) []*Node {
	out := make([]*Node, 0, args.NamedChildCount())
	for _, c := range args.NamedChildren() {
		if c.Type() == "comment" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// sinkLiteral returns the value of a string literal, or of a template
// literal that has no substitutions in it. The second return value is
// false for anything else.
func sinkLiteral(n *Node) (string, bool) {
	if !n.IsValid() {
		return "", false
	}

	switch n.Type() {
	case "string":
		return n.RawString(), true
	case "template_string":
		c := n.Content()
		if strings.Contains(c, "${") {
			return "", false
		}
		return dequote(c), true
	}
	return "", false
}

// sinkIsEmptyString returns true for an empty string literal,
// whichever kind of quotes it uses.
func sinkIsEmptyString(n *Node) bool {
	if !n.IsValid() || n.node.EndByte()-n.node.StartByte() != 2 {
		return false
	}

	switch n.Content() {
	case `""`, `''`, "``":
		return true
	}
	return false
}

// sinkIsStringy returns true for expressions that are certainly strings:
// string literals, template literals, and string concatenations
// containing either of those.
func sinkIsStringy(n *Node) bool {
	if !n.IsValid() {
		return false
	}

	switch n.Type() {
	case "string", "template_string":
		return true

	case "binary_expression":
		// "code(" + x + ")"; x + "()" is just as much a string
		if n.ChildByFieldName("operator").Content() != "+" {
			return false
		}
		return sinkIsStringy(n.ChildByFieldName("left")) ||
			sinkIsStringy(n.ChildByFieldName("right"))

	case "parenthesized_expression":
		return sinkIsStringy(n.NamedChild(0))
	}
	return false
}

// sinkIsGlobal returns true if a node is one of the global objects
// like window or self
func sinkIsGlobal(n *Node) bool {
	return n.IsValid() && n.Type() == "identifier" && sinkGlobalObjects.Contains(n.Content())
}

// sinkIsDocument returns true if a node is the document; either
// document itself or something.document, like window.document
func sinkIsDocument(n *Node) bool {
	if !n.IsValid() {
		return false
	}

	switch n.Type() {
	case "identifier":
		return n.Content() == "document"
	case "member_expression", "subscript_expression":
		return sinkPropName(n) == "document"
	}
	return false
}

// sinkIsDangerousAttribute returns true for the attributes that
// setAttribute can use to navigate, load content, or run script.
func sinkIsDangerousAttribute(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if sinkSetAttributeNames.Contains(name) {
		return true
	}

	// any other event handler: onclick, onmouseover etc
	if len(name) > 2 && strings.HasPrefix(name, "on") {
		for _, r := range name[2:] {
			if r < 'a' || r > 'z' {
				return false
			}
		}
		return true
	}
	return false
}

// sinkIsDocumentWrite works out whether a call to a method called write
// is likely to be document.write, and not the write method of a stream or a
// socket. It is if it's called on something with 'doc' in its name, or
// if what is written looks like markup or contains a source.
func sinkIsDocumentWrite(recv *Node, args []*Node) bool {
	if strings.Contains(strings.ToLower(sinkHead(recv, 200)), "doc") {
		return true
	}

	for _, arg := range args {
		if strings.Contains(sinkHead(arg, 2048), "<") {
			return true
		}
	}

	tainted, _ := sinkTaintNodes(nil, args...)
	return tainted
}

// sinkIsNameValueCall returns true for calls that look like
// FormData.append(name, value) or URLSearchParams.append(name, value)
// rather than jQuery's .append(content), which is far more commonly
// called with a single argument. Calls with an HTML string as the
// first argument are never treated as name/value calls.
func sinkIsNameValueCall(args []*Node) bool {
	if len(args) < 2 {
		return false
	}
	return !(args[0].Type() == "string" && strings.Contains(args[0].Content(), "<"))
}

// sinkAllFunctions returns true if every argument is a function; things like
// $.before(function(){...}) are callbacks and don't take HTML
func sinkAllFunctions(args []*Node) bool {
	for _, a := range args {
		switch a.Type() {
		case "function", "function_expression", "arrow_function", "generator_function":
		default:
			return false
		}
	}
	return len(args) > 0
}
