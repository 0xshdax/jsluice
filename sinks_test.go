package jsluice

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// sinkTestDump returns a string representation of some sinks for test failures
func sinkTestDump(sinks []*Sink) string {
	j, err := json.Marshal(sinks)
	if err != nil {
		return err.Error()
	}
	return string(j)
}

func TestGetSinks(t *testing.T) {
	// A blank kind means that no sinks are expected at all. In every other
	// case the JavaScript must contain exactly one sink.
	cases := []struct {
		name     string
		js       string
		kind     string
		tainted  bool
		taint    string
		severity Severity
	}{
		// innerHTML and friends
		{"innerHTML tainted", `el.innerHTML = location.hash`, "innerHTML", true, "location.hash", SeverityHigh},
		{"innerHTML static", `x.innerHTML = "<b>static</b>"`, "innerHTML", false, "", SeverityMedium},
		{"innerHTML variable", `x.innerHTML = html`, "innerHTML", false, "", SeverityMedium},
		{"innerHTML concatenation", `el.innerHTML = "<b>" + decodeURIComponent(q) + "</b>"`, "innerHTML", true, "decodeURIComponent", SeverityHigh},
		{"innerHTML template literal", "el.innerHTML = `<i>${window.location.search}</i>`", "innerHTML", true, "location.search", SeverityHigh},
		{"innerHTML append", `el.innerHTML += document.referrer`, "innerHTML", true, "document.referrer", SeverityHigh},
		{"innerHTML or-assign", `el.innerHTML ||= document.URL`, "innerHTML", true, "document.URL", SeverityHigh},
		{"innerHTML subscript", `el["innerHTML"] = window.name`, "innerHTML", true, "window.name", SeverityHigh},
		{"innerHTML chained member", `document.getElementById("x").innerHTML = atob(s)`, "innerHTML", true, "atob", SeverityHigh},
		{"innerHTML empty string", `el.innerHTML = ""`, "", false, "", ""},
		{"innerHTML empty single quotes", `el.innerHTML = ''`, "", false, "", ""},
		{"innerHTML minus-assign", `el.innerHTML -= 1`, "", false, "", ""},
		{"innerHTML read", `var h = el.innerHTML`, "", false, "", ""},
		{"outerHTML", `el.outerHTML = location.href`, "outerHTML", true, "location.href", SeverityHigh},
		{"outerHTML static", `el.outerHTML = "<p></p>"`, "outerHTML", false, "", SeverityMedium},

		// src, srcdoc, href, cookie
		{"src tainted", `script.src = location.hash.slice(1)`, "src", true, "location.hash", SeverityMedium},
		{"src static", `img.src = "/logo.png"`, "src", false, "", SeverityLow},
		{"srcdoc", `frame.srcdoc = x`, "srcdoc", false, "", SeverityLow},
		{"srcdoc tainted", `frame.srcdoc = "<p>" + location.search`, "srcdoc", true, "location.search", SeverityMedium},
		{"href tainted", `a.href = location.search`, "href", true, "location.search", SeverityMedium},
		{"href navigation", `location.href = url`, "href", false, "", SeverityLow},
		{"documentCookie tainted", `document.cookie = "a=" + location.hash`, "documentCookie", true, "location.hash", SeverityMedium},
		{"documentCookie static", `document.cookie = "a=1; path=/"`, "documentCookie", false, "", SeverityLow},
		{"documentCookie window.document", `window.document.cookie = "a=1"`, "documentCookie", false, "", SeverityLow},
		{"documentCookie read", `var c = document.cookie`, "", false, "", ""},
		{"cookie on something else", `req.cookie = "a=1"`, "", false, "", ""},
		{"other property", `el.textContent = location.hash`, "", false, "", ""},
		{"other assignment", `x = location.hash`, "", false, "", ""},

		// document.write and insertAdjacentHTML
		{"document.write tainted", `document.write(location.search)`, "documentWrite", true, "location.search", SeverityHigh},
		{"document.writeln static", `document.writeln("<b>x</b>")`, "documentWrite", false, "", SeverityMedium},
		{"document.write no arguments", `document.write()`, "", false, "", ""},
		{"write is not a sink without a receiver", `write(location.hash)`, "", false, "", ""},
		{"document.write tagged template", "document.write`<b>${x}</b>`", "", false, "", ""},
		{"window.document.write", `window.document.write(html)`, "documentWrite", false, "", SeverityMedium},
		{"iframe document.write", `iframe.contentWindow.document.write(html)`, "documentWrite", false, "", SeverityMedium},
		{"contentDocument.write", `frame.contentDocument.write(html)`, "documentWrite", false, "", SeverityMedium},
		{"doc alias write", `doc.write(html)`, "documentWrite", false, "", SeverityMedium},
		{"aliased document write of markup", `d.write("<script src=x></script>")`, "documentWrite", false, "", SeverityMedium},
		{"aliased document write of a source", `d.write(location.hash)`, "documentWrite", true, "location.hash", SeverityHigh},
		{"stream write", `stream.write(chunk, encoding)`, "", false, "", ""},
		{"this.write is a stream", `this.write(chunk)`, "", false, "", ""},
		{"super.write is a stream", `super.write(chunk)`, "", false, "", ""},
		{"socket write", `this.socket.write(buff.toBuffer())`, "", false, "", ""},
		{"insertAdjacentHTML", `node.insertAdjacentHTML("beforeend", userIn)`, "insertAdjacentHTML", false, "", SeverityMedium},
		{"insertAdjacentHTML tainted", `node.insertAdjacentHTML("beforeend", document.referrer)`, "insertAdjacentHTML", true, "document.referrer", SeverityHigh},
		{"insertAdjacentHTML optional chain", `node?.insertAdjacentHTML("afterend", location.hash)`, "insertAdjacentHTML", true, "location.hash", SeverityHigh},
		{"insertAdjacentHTML subscript", `node["insertAdjacentHTML"]("afterend", location.hash)`, "insertAdjacentHTML", true, "location.hash", SeverityHigh},
		{"insertAdjacentHTML position is not the payload", `node.insertAdjacentHTML(location.hash, "<b>x</b>")`, "insertAdjacentHTML", false, "", SeverityMedium},

		// jQuery
		{"jQuery html", `$("#x").html(foo)`, "jQueryHtml", false, "", SeverityMedium},
		{"jQuery html tainted", `$("#x").html(location.hash)`, "jQueryHtml", true, "location.hash", SeverityHigh},
		{"jQuery html template literal", "jQuery(el).html(`<i>${location.search}</i>`)", "jQueryHtml", true, "location.search", SeverityHigh},
		{"jQuery html getter", `var h = $("#x").html()`, "", false, "", ""},
		{"jQuery append", `$(el).append("<b>x</b>")`, "jQueryManip", false, "", SeverityLow},
		{"jQuery append tainted", `$(el).append(location.hash)`, "jQueryManip", true, "location.hash", SeverityMedium},
		{"jQuery prepend", `$(el).prepend(x)`, "jQueryManip", false, "", SeverityLow},
		{"jQuery after", `$(el).after(x)`, "jQueryManip", false, "", SeverityLow},
		{"jQuery before", `$(el).before(x)`, "jQueryManip", false, "", SeverityLow},
		{"jQuery replaceWith", `$(el).replaceWith(x)`, "jQueryManip", false, "", SeverityLow},
		{"jQuery wrap", `$(el).wrap(x)`, "jQueryManip", false, "", SeverityLow},
		{"jQuery append HTML with a second argument", `$(el).append("<b>", location.hash)`, "jQueryManip", true, "location.hash", SeverityMedium},
		{"FormData append is not a sink", `fd.append("name", location.hash)`, "", false, "", ""},
		{"URLSearchParams append is not a sink", `t.append(decodeURIComponent(r), decodeURIComponent(a))`, "", false, "", ""},
		{"append of two nodes is not a sink", `parent.append(a, b)`, "", false, "", ""},
		{"callback to before is not a sink", `$(el).before(function(){ go() })`, "", false, "", ""},
		{"append without a receiver", `append(x)`, "", false, "", ""},

		// setAttribute
		{"setAttribute href", `el.setAttribute("href", location.search)`, "setAttribute", true, "location.search", SeverityMedium},
		{"setAttribute src", `el.setAttribute('src', x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute srcdoc", `el.setAttribute("srcdoc", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute action", `form.setAttribute("action", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute formaction", `btn.setAttribute("formaction", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute onload", `el.setAttribute("onload", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute onerror", `el.setAttribute("onerror", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute data", `obj.setAttribute("data", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute xlink:href", `use.setAttribute("xlink:href", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute other event handler", `el.setAttribute("onclick", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute case-insensitive", `el.setAttribute("HREF", x)`, "setAttribute", false, "", SeverityLow},
		{"setAttribute template literal name", "el.setAttribute(`href`, x)", "setAttribute", false, "", SeverityLow},
		{"setAttribute harmless attribute", `el.setAttribute("class", location.hash)`, "", false, "", ""},
		{"setAttribute attribute name is not the payload", `el.setAttribute("href", "/home")`, "setAttribute", false, "", SeverityLow},
		{"setAttribute dynamic attribute", `el.setAttribute(name, location.hash)`, "", false, "", ""},
		{"setAttribute online is not an event handler", `el.setAttribute("on-line", x)`, "", false, "", ""},
		{"setAttribute one argument", `el.setAttribute("href")`, "", false, "", ""},

		// eval and friends
		{"eval", `eval(a)`, "eval", false, "", SeverityMedium},
		{"eval tainted", `eval(location.hash.slice(1))`, "eval", true, "location.hash", SeverityHigh},
		{"eval of unescape", `eval(unescape(s))`, "eval", true, "unescape", SeverityHigh},
		{"eval with comment", `eval(/* hi */ x)`, "eval", false, "", SeverityMedium},
		{"eval no arguments", `eval()`, "", false, "", ""},
		{"window.eval", `window.eval(x)`, "eval", false, "", SeverityMedium},
		{"indirect eval", `(0, eval)(x)`, "eval", false, "", SeverityMedium},
		{"indirect eval of window.eval", `(0, window.eval)(location.hash)`, "eval", true, "location.hash", SeverityHigh},
		{"eval method on something else", `engine.eval(x)`, "", false, "", ""},
		{"setTimeout string", `setTimeout("code()",10)`, "setTimeoutString", false, "", SeverityMedium},
		{"setTimeout concatenation", `setTimeout("go(" + location.hash + ")", 5)`, "setTimeoutString", true, "location.hash", SeverityHigh},
		{"setTimeout reversed concatenation", `setTimeout(name + "()", 5)`, "setTimeoutString", false, "", SeverityMedium},
		{"setTimeout template literal", "setTimeout(`go(${x})`, 5)", "setTimeoutString", false, "", SeverityMedium},
		{"setTimeout window", `window.setTimeout("x()", 1)`, "setTimeoutString", false, "", SeverityMedium},
		{"setTimeout delay is not the payload", `setTimeout("x()", location.hash)`, "setTimeoutString", false, "", SeverityMedium},
		{"setTimeout function reference", `setTimeout(fn,10)`, "", false, "", ""},
		{"setTimeout function expression", `setTimeout(function(){ a() }, 10)`, "", false, "", ""},
		{"setTimeout arrow function", `setTimeout(() => a(), 10)`, "", false, "", ""},
		{"setTimeout numeric addition", `setTimeout(a + b, 10)`, "", false, "", ""},
		{"setTimeout on something else", `timers.setTimeout("x()", 10)`, "", false, "", ""},
		{"setInterval string", `setInterval("tick()", 1000)`, "setIntervalString", false, "", SeverityMedium},
		{"setInterval function", `setInterval(tick, 1000)`, "", false, "", ""},
		{"new Function", `new Function("a", "return a")`, "Function", false, "", SeverityMedium},
		{"new Function tainted", `new Function("return " + location.hash)`, "Function", true, "location.hash", SeverityHigh},
		{"new window.Function", `new window.Function("x")`, "Function", false, "", SeverityMedium},
		{"Function without new", `Function("return this")()`, "Function", false, "", SeverityMedium},
		{"new Function no arguments", `new Function()`, "", false, "", ""},
		{"new Function without parentheses", `new Function`, "", false, "", ""},
		{"new something else", `new Widget("return 1")`, "", false, "", ""},

		// DOMParser
		{"DOMParser", `new DOMParser().parseFromString(x, "text/html")`, "DOMParser", false, "", SeverityLow},
		{"DOMParser tainted", `parser.parseFromString(location.hash, "text/html")`, "DOMParser", true, "location.hash", SeverityMedium},
		{"DOMParser mime type is case-insensitive", `parser.parseFromString(x, 'Text/HTML')`, "DOMParser", false, "", SeverityLow},
		{"DOMParser xml", `parser.parseFromString(x, "text/xml")`, "", false, "", ""},
		{"DOMParser dynamic mime type", `parser.parseFromString(x, type)`, "", false, "", ""},

		// React
		{"dangerouslySetInnerHTML", `React.createElement("div", {dangerouslySetInnerHTML:{__html:data}})`, "dangerouslySetInnerHTML", false, "", SeverityMedium},
		{"dangerouslySetInnerHTML tainted", `React.createElement("div", {dangerouslySetInnerHTML:{__html:location.hash}})`, "dangerouslySetInnerHTML", true, "location.hash", SeverityHigh},
		{"dangerouslySetInnerHTML string key", `x = {"dangerouslySetInnerHTML": {"__html": decodeURIComponent(d)}}`, "dangerouslySetInnerHTML", true, "decodeURIComponent", SeverityHigh},
		{"dangerouslySetInnerHTML function call", `props = {dangerouslySetInnerHTML: markup(location.search)}`, "dangerouslySetInnerHTML", true, "location.search", SeverityHigh},
		{"dangerouslySetInnerHTML minified", `e.createElement("div",{className:"c",dangerouslySetInnerHTML:{__html:t}})`, "dangerouslySetInnerHTML", false, "", SeverityMedium},
		{"dangerouslySetInnerHTML jsx", `x = <div dangerouslySetInnerHTML={{__html: html}} />`, "dangerouslySetInnerHTML", false, "", SeverityMedium},
		{"dangerouslySetInnerHTML jsx tainted", `x = <div dangerouslySetInnerHTML={{__html: location.search}}></div>`, "dangerouslySetInnerHTML", true, "location.search", SeverityHigh},
		{"dangerouslySetInnerHTML jsx expression", `x = <p dangerouslySetInnerHTML={this.props.markup}></p>`, "dangerouslySetInnerHTML", false, "", SeverityMedium},
		{"other jsx attribute", `x = <div className={location.hash} />`, "", false, "", ""},
		{"other object key", `x = {innerHTML: location.hash}`, "", false, "", ""},
		{"__html on its own", `x = {__html: location.hash}`, "", false, "", ""},

		// postMessage is somebody else's job
		{"postMessage call", `window.postMessage(data, "*")`, "", false, "", ""},
		{"message listener", `window.addEventListener("message", function(e){ go(e.data) })`, "", false, "", ""},
		{"onmessage", `window.onmessage = function(e){ go(e.data) }`, "", false, "", ""},

		// taint has to be a source, not just something that looks a bit like one
		{"geolocation is not location", `el.innerHTML = geolocation.coords`, "innerHTML", false, "", SeverityMedium},
		{"relocation is not location", `el.innerHTML = relocation`, "innerHTML", false, "", SeverityMedium},
		{"locations is not location", `el.innerHTML = locations[0]`, "innerHTML", false, "", SeverityMedium},
		{"bare location", `el.innerHTML = String(location)`, "innerHTML", true, "location", SeverityHigh},
		{"props.location.pathname", `el.innerHTML = this.props.location.pathname`, "innerHTML", true, "location.pathname", SeverityHigh},
		{"bare .hash", `el.innerHTML = a.hash`, "innerHTML", true, ".hash", SeverityHigh},
		{"hashCode is not .hash", `el.innerHTML = a.hashCode`, "innerHTML", false, "", SeverityMedium},
		{"bare .search", `el.innerHTML = a.search`, "innerHTML", true, ".search", SeverityHigh},
		{"searchInput is not .search", `el.innerHTML = this.searchInput.value`, "innerHTML", false, "", SeverityMedium},
		{"css class is not .search", `el.innerHTML = $(".search-box").val()`, "innerHTML", false, "", SeverityMedium},
		{"css descendant is not .hash", `el.innerHTML = $("li .hash-link").text()`, "innerHTML", false, "", SeverityMedium},
		{".search after a call", `el.innerHTML = getUrl().search`, "innerHTML", true, ".search", SeverityHigh},
		{".hash after an index", `el.innerHTML = links[0].hash`, "innerHTML", true, ".hash", SeverityHigh},
		{"searchParams", `el.innerHTML = url.searchParams.get("q")`, "innerHTML", true, ".searchParams", SeverityHigh},
		{"URLSearchParams", `el.innerHTML = new URLSearchParams(s).get("q")`, "innerHTML", true, "URLSearchParams", SeverityHigh},
		{"document.documentURI", `el.innerHTML = document.documentURI`, "innerHTML", true, "document.documentURI", SeverityHigh},
		{"document.cookie as a source", `el.innerHTML = document.cookie`, "innerHTML", true, "document.cookie", SeverityHigh},
		{"most specific source wins", `el.innerHTML = decodeURIComponent(window.location.hash)`, "innerHTML", true, "location.hash", SeverityHigh},

		// ...and a source mentioned in a string, a comment or a regular
		// expression is not one either, because none of those are code
		{"source in a string", `el.innerHTML = "Enter your location"`, "innerHTML", false, "", SeverityMedium},
		{"source in a string key", `$("#alt").html(gps["kismet.common.location.alt"] / 1000)`, "jQueryHtml", false, "", SeverityMedium},
		{"source in a string with escaped quotes", `el.innerHTML = "say \"location.hash\" now"`, "innerHTML", false, "", SeverityMedium},
		{"source in a regular expression", `el.innerHTML = x.replace(/location.hash/g, "")`, "innerHTML", false, "", SeverityMedium},
		{"source in template literal text", "el.innerHTML = `Your location is ${place}`", "innerHTML", false, "", SeverityMedium},
		{"source in a template substitution", "el.innerHTML = `Your hash is ${location.hash}`", "innerHTML", true, "location.hash", SeverityHigh},
		{"source in a nested template substitution", "el.innerHTML = `a${`b${atob(c)}`}`", "innerHTML", true, "atob", SeverityHigh},
		{"string in a template substitution", "el.innerHTML = `a${'location.hash'}b`", "innerHTML", false, "", SeverityMedium},
		{"source after a string", `el.innerHTML = "location " + 'x' + location.hash`, "innerHTML", true, "location.hash", SeverityHigh},
		{"source in a comment", "el.innerHTML = x + /* location.hash */ y", "innerHTML", false, "", SeverityMedium},
		{"source in eval of a string", `eval("var h = location.hash; module.exports = decodeURIComponent(h)")`, "eval", false, "", SeverityMedium},
		{"source in the code string of setTimeout", `setTimeout("go(location.hash)", 5)`, "setTimeoutString", false, "", SeverityMedium},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sinks := NewAnalyzer([]byte(c.js)).GetSinks()

			if c.kind == "" {
				if len(sinks) != 0 {
					t.Fatalf("want no sinks for %q; have %d: %s", c.js, len(sinks), sinkTestDump(sinks))
				}
				return
			}

			if len(sinks) != 1 {
				t.Fatalf("want exactly 1 sink for %q; have %d: %s", c.js, len(sinks), sinkTestDump(sinks))
			}
			s := sinks[0]

			if s.Kind != c.kind {
				t.Errorf("want kind %s for %q; have %s", c.kind, c.js, s.Kind)
			}
			if s.Tainted != c.tainted {
				t.Errorf("want tainted=%t for %q; have %t", c.tainted, c.js, s.Tainted)
			}
			if s.Taint != c.taint {
				t.Errorf("want taint %q for %q; have %q", c.taint, c.js, s.Taint)
			}
			if s.Severity != c.severity {
				t.Errorf("want severity %s for %q; have %s", c.severity, c.js, s.Severity)
			}
			if s.Line != 1 {
				t.Errorf("want line 1 for %q; have %d", c.js, s.Line)
			}
			if s.Source == "" {
				t.Errorf("want a source for %q; have none", c.js)
			}
			if s.Filename != "" {
				t.Errorf("want no filename for %q; have %q", c.js, s.Filename)
			}
		})
	}
}

func TestGetSinksLinesAndOrder(t *testing.T) {
	js := `var a = 1;

el.innerHTML = location.hash;
function f() {
	document.write(
		"<b>" + x
	);
	setTimeout("again()", 100);
}
$("#out").html(foo)
`

	expected := []struct {
		kind string
		line int
	}{
		{"innerHTML", 3},
		{"documentWrite", 5},
		{"setTimeoutString", 8},
		{"jQueryHtml", 10},
	}

	sinks := NewAnalyzer([]byte(js)).GetSinks()
	if len(sinks) != len(expected) {
		t.Fatalf("want %d sinks; have %d: %s", len(expected), len(sinks), sinkTestDump(sinks))
	}

	for i, e := range expected {
		if sinks[i].Kind != e.kind || sinks[i].Line != e.line {
			t.Errorf("want %s on line %d for sink %d; have %s on line %d", e.kind, e.line, i, sinks[i].Kind, sinks[i].Line)
		}
	}

	// the source is that of the whole sink, not just the first line
	if !strings.Contains(sinks[1].Source, "\"<b>\" + x") {
		t.Errorf("want the whole document.write call in the source; have %q", sinks[1].Source)
	}
}

func TestGetSinksMultiple(t *testing.T) {
	// one statement can contain several sinks
	js := `$(el).html(location.hash); el.innerHTML = $(x).html(y)`

	sinks := NewAnalyzer([]byte(js)).GetSinks()

	kinds := make([]string, 0, len(sinks))
	for _, s := range sinks {
		kinds = append(kinds, s.Kind)
	}

	// results are in the order they appear in the source,
	// outer expressions before the ones nested inside them
	expected := "jQueryHtml,innerHTML,jQueryHtml"
	if strings.Join(kinds, ",") != expected {
		t.Errorf("want sinks %s; have %s", expected, strings.Join(kinds, ","))
	}
}

func TestGetSinksNested(t *testing.T) {
	// The code for sinks nested inside others comes from the outer sink, so
	// check the results are the same as if each was worked out on its own
	cases := []struct {
		name    string
		js      string
		tainted []bool
	}{
		{"both tainted", `$(a).html("location " + $(b).html(location.hash))`, []bool{true, true}},
		{"only the inner is tainted", `$(a).html(f($(b).html(location.hash)))`, []bool{true, true}},
		{"neither tainted", `$(a).html("location" + $(b).html(x))`, []bool{false, false}},
		{"source in a string of the inner", `$(a).html(f($(b).html("a location b")))`, []bool{false, false}},
		{"source in a string of the outer", `$(a).html(f("a location b", $(b).html(x)))`, []bool{false, false}},
		{"siblings", `$(a).html("location"); $(b).html(location.hash)`, []bool{false, true}},
		{"siblings the other way", `$(a).html(location.hash); $(b).html("location")`, []bool{true, false}},
		{"nested in a template", "$(a).html(`x ${$(b).html(location.hash)} y location`)", []bool{true, true}},
		{"after the nesting", `$(a).html(f($(b).html(x), "location")); $(c).html(location.search)`, []bool{false, false, true}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sinks := NewAnalyzer([]byte(c.js)).GetSinks()
			if len(sinks) != len(c.tainted) {
				t.Fatalf("want %d sinks for %q; have %d: %s", len(c.tainted), c.js, len(sinks), sinkTestDump(sinks))
			}
			for i, s := range sinks {
				if s.Tainted != c.tainted[i] {
					t.Errorf("want sink %d of %q to have tainted=%t; have %t (%q)", i, c.js, c.tainted[i], s.Tainted, s.Source)
				}
			}
		})
	}
}

func TestGetSinksDeeplyNested(t *testing.T) {
	// finding the code in every one of the sinks nested inside the others
	// must not mean going over all of it again, or this takes minutes
	depth := 3000
	js := strings.Repeat("$(a).html(", depth) + "location.hash" + strings.Repeat(")", depth)

	start := time.Now()
	sinks := NewAnalyzer([]byte(js)).GetSinks()
	elapsed := time.Since(start)

	if len(sinks) == 0 {
		t.Fatal("want sinks; have none")
	}
	for _, s := range sinks {
		if s.Kind != "jQueryHtml" || !s.Tainted || s.Taint != "location.hash" {
			t.Fatalf("want every sink to be tainted jQueryHtml; have %s", sinkTestDump([]*Sink{s}))
		}
	}
	if elapsed > 10*time.Second {
		t.Errorf("want nested sinks to take well under 10 seconds; took %s", elapsed)
	}
}

func TestGetSinksManyArguments(t *testing.T) {
	// a call with a huge number of arguments mustn't take forever
	count := 50000
	js := "document.write(" + strings.Repeat("1,", count) + "location.hash)"

	start := time.Now()
	sinks := NewAnalyzer([]byte(js)).GetSinks()
	elapsed := time.Since(start)

	if len(sinks) != 1 || sinks[0].Kind != "documentWrite" || !sinks[0].Tainted || sinks[0].Taint != "location.hash" {
		t.Fatalf("want one tainted documentWrite; have %s", sinkTestDump(sinks))
	}
	if elapsed > 10*time.Second {
		t.Errorf("want a call with %d arguments to take well under 10 seconds; took %s", count, elapsed)
	}
}

func TestSinkBlankStaysInsideTheSubtree(t *testing.T) {
	js := "a(\"x\"); b(location, \"y\", `t${'u'}v`); c(\"z\")"

	// program > expression_statement > call_expression
	call := NewAnalyzer([]byte(js)).RootNode().NamedChild(1).NamedChild(0)
	if call.Type() != "call_expression" || !strings.HasPrefix(call.Content(), "b(") {
		t.Fatalf("want the call to b; have %s %q", call.Type(), call.Content())
	}

	// Blank out the whole of the source, but only for the tree under b(...).
	// The strings in a() and c() are outside of that so must be left alone.
	buf := []byte(js)
	sinkBlank(call.node, call.source, buf, 0)

	expected := "a(\"x\"); b(location, " + "   " + ", " + "  ${   }  " + "); c(\"z\")"
	if string(buf) != expected {
		t.Errorf("want\n%q\nhave\n%q", expected, buf)
	}

	// and the same when working on a copy of just the call, as sinkMask does
	if code := (*sinkMask)(nil).codeFor(call); code != expected[strings.Index(expected, "b("):strings.Index(expected, "; c(")] {
		t.Errorf("want only the code of the call; have %q", code)
	}
}

func TestGetSinksDeduplicates(t *testing.T) {
	// the same sink more than once on the same line is only reported once...
	sinks := NewAnalyzer([]byte(`a.innerHTML=x;a.innerHTML=x;a.innerHTML=y;`)).GetSinks()
	if len(sinks) != 2 {
		t.Errorf("want 2 sinks for the same line; have %d: %s", len(sinks), sinkTestDump(sinks))
	}

	// ...but is reported once per line
	sinks = NewAnalyzer([]byte("a.innerHTML=x;\na.innerHTML=x;")).GetSinks()
	if len(sinks) != 2 {
		t.Errorf("want 2 sinks for different lines; have %d: %s", len(sinks), sinkTestDump(sinks))
	}
}

func TestGetSinksNothingToFind(t *testing.T) {
	for _, js := range []string{
		``,
		`var a = 1;`,
		`function f(x) { return x + 1 }`,
		`el.textContent = location.hash; console.log(document.cookie);`,
		`this is not valid JavaScript {{{`,
	} {
		sinks := NewAnalyzer([]byte(js)).GetSinks()

		// callers should get an empty slice and not nil, so that
		// JSON encoding it gives [] and not null
		if sinks == nil {
			t.Errorf("want an empty slice for %q; have nil", js)
		}
		if len(sinks) != 0 {
			t.Errorf("want no sinks for %q; have %s", js, sinkTestDump(sinks))
		}
	}
}

func TestGetSinksInlineScripts(t *testing.T) {
	html := `<!doctype html>
<html><body>
<script>
  document.getElementById("out").innerHTML = location.hash;
</script>
</body></html>`

	sinks := NewAnalyzer([]byte(html)).GetSinks()
	if len(sinks) != 1 {
		t.Fatalf("want 1 sink in the inline script; have %d: %s", len(sinks), sinkTestDump(sinks))
	}
	if sinks[0].Kind != "innerHTML" || !sinks[0].Tainted {
		t.Errorf("want a tainted innerHTML sink; have %s", sinkTestDump(sinks))
	}
}

func TestGetSinksSourceTruncated(t *testing.T) {
	long := strings.Repeat("a", 2000)

	sinks := NewAnalyzer([]byte(`el.innerHTML = "` + long + `"`)).GetSinks()
	if len(sinks) != 1 {
		t.Fatalf("want 1 sink; have %d", len(sinks))
	}

	src := sinks[0].Source
	if len(src) > 400 {
		t.Errorf("want source of at most 400 bytes; have %d", len(src))
	}
	if !strings.HasPrefix(src, "el.innerHTML = ") {
		t.Errorf("want source to start with the sink; have %q", src)
	}
	if !strings.HasSuffix(src, "...") {
		t.Errorf("want truncated source to end with an ellipsis; have %q", src)
	}

	// short sinks must be left alone
	sinks = NewAnalyzer([]byte(`el.innerHTML = "short"`)).GetSinks()
	if sinks[0].Source != `el.innerHTML = "short"` {
		t.Errorf("want source untouched; have %q", sinks[0].Source)
	}

	// as must sinks of exactly the maximum length
	exact := `el.innerHTML = "` + strings.Repeat("b", sinkMaxSource-len(`el.innerHTML = ""`)) + `"`
	sinks = NewAnalyzer([]byte(exact)).GetSinks()
	if len(exact) != sinkMaxSource || sinks[0].Source != exact {
		t.Errorf("want a source of exactly %d bytes to be left alone; have %d bytes", sinkMaxSource, len(sinks[0].Source))
	}
}

func TestGetSinksSourceTruncatedMultibyte(t *testing.T) {
	// every character is 3 bytes, so no matter where the
	// cut lands it can't be allowed to split one
	for pad := 0; pad < 3; pad++ {
		js := `el.innerHTML = "` + strings.Repeat("a", pad) + strings.Repeat("☃", 500) + `"`

		sinks := NewAnalyzer([]byte(js)).GetSinks()
		if len(sinks) != 1 {
			t.Fatalf("want 1 sink; have %d", len(sinks))
		}

		src := sinks[0].Source
		if !utf8.ValidString(src) {
			t.Errorf("pad %d: want valid UTF-8 after truncation; have %q", pad, src)
		}
		if len(src) > 400 {
			t.Errorf("pad %d: want source of at most 400 bytes; have %d", pad, len(src))
		}
	}
}

func TestSinkJSON(t *testing.T) {
	sink := &Sink{
		Kind:     "innerHTML",
		Severity: SeverityHigh,
		Tainted:  true,
		Taint:    "location.hash",
		Line:     12,
		Source:   "el.innerHTML = location.hash",
		Filename: "app.js",
	}

	j, err := json.Marshal(sink)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"kind":"innerHTML","severity":"high","tainted":true,"taint":"location.hash","line":12,"source":"el.innerHTML = location.hash","filename":"app.js"}`
	if string(j) != expected {
		t.Errorf("want JSON %s; have %s", expected, j)
	}

	// taint and filename are optional; the rest are always there
	j, err = json.Marshal(&Sink{Kind: "eval", Severity: SeverityMedium, Line: 1, Source: "eval(a)"})
	if err != nil {
		t.Fatal(err)
	}

	expected = `{"kind":"eval","severity":"medium","tainted":false,"line":1,"source":"eval(a)"}`
	if string(j) != expected {
		t.Errorf("want JSON %s; have %s", expected, j)
	}
}

func TestSinkSeverity(t *testing.T) {
	cases := []struct {
		kind      string
		untainted Severity
		tainted   Severity
	}{
		{sinkKindInnerHTML, SeverityMedium, SeverityHigh},
		{sinkKindOuterHTML, SeverityMedium, SeverityHigh},
		{sinkKindDocumentWrite, SeverityMedium, SeverityHigh},
		{sinkKindInsertAdjacentHTML, SeverityMedium, SeverityHigh},
		{sinkKindJQueryHTML, SeverityMedium, SeverityHigh},
		{sinkKindDangerouslySetInnerHTML, SeverityMedium, SeverityHigh},
		{sinkKindEval, SeverityMedium, SeverityHigh},
		{sinkKindFunction, SeverityMedium, SeverityHigh},
		{sinkKindSetTimeoutString, SeverityMedium, SeverityHigh},
		{sinkKindSetIntervalString, SeverityMedium, SeverityHigh},
		{sinkKindSrc, SeverityLow, SeverityMedium},
		{sinkKindSrcdoc, SeverityLow, SeverityMedium},
		{sinkKindHref, SeverityLow, SeverityMedium},
		{sinkKindSetAttribute, SeverityLow, SeverityMedium},
		{sinkKindDocumentCookie, SeverityLow, SeverityMedium},
		{sinkKindJQueryManip, SeverityLow, SeverityMedium},
		{sinkKindDOMParser, SeverityLow, SeverityMedium},
	}

	for _, c := range cases {
		if have := sinkSeverity(c.kind, false); have != c.untainted {
			t.Errorf("want %s for untainted %s; have %s", c.untainted, c.kind, have)
		}
		if have := sinkSeverity(c.kind, true); have != c.tainted {
			t.Errorf("want %s for tainted %s; have %s", c.tainted, c.kind, have)
		}
	}
}

func TestSinkTaint(t *testing.T) {
	cases := []struct {
		js      string
		tainted bool
		taint   string
	}{
		// every source, in the order they are looked for
		{`location.hash`, true, "location.hash"},
		{`location.search`, true, "location.search"},
		{`location.href`, true, "location.href"},
		{`location.pathname`, true, "location.pathname"},
		{`location`, true, "location"},
		{`document.URL`, true, "document.URL"},
		{`document.documentURI`, true, "document.documentURI"},
		{`document.referrer`, true, "document.referrer"},
		{`document.cookie`, true, "document.cookie"},
		{`window.name`, true, "window.name"},
		{`new URLSearchParams(x)`, true, "URLSearchParams"},
		{`decodeURIComponent(x)`, true, "decodeURIComponent"},
		{`unescape(x)`, true, "unescape"},
		{`atob(x)`, true, "atob"},
		{`x.hash`, true, ".hash"},
		{`x.search`, true, ".search"},
		{`getUrl().search`, true, ".search"},
		{`links[0].hash`, true, ".hash"},
		{`url.searchParams.get("q")`, true, ".searchParams"},

		// sources are found wherever they are
		{`window.top.location.hash.substr(1)`, true, "location.hash"},
		{`a + b + document.referrer + c`, true, "document.referrer"},
		{"`<b>${location.search}</b>`", true, "location.search"},
		{`decodeURIComponent(location.search)`, true, "location.search"},
		{`foo(location, location.hash)`, true, "location.hash"},

		// a failed match at the start mustn't hide a later one
		{`geolocation + location.hash`, true, "location.hash"},
		{`relocation.hash + location`, true, "location"},

		// strings, templates, regular expressions and comments aren't code
		{`'a' + location`, true, "location"},
		{`"location.hash"`, false, ""},
		{`'Enter your location'`, false, ""},
		{`x['kismet.common.location.alt']`, false, ""},
		{`/location.hash/.test(x)`, false, ""},
		{"`location.hash`", false, ""},
		{"`${location.hash}`", true, "location.hash"},
		{"`a ${b} location ${c}`", false, ""},
		{"`${'location.hash'}`", false, ""},
		{"`a${`b${location.search}`}c`", true, "location.search"},
		{`"\"" + location.hash + "\""`, true, "location.hash"},
		{`"it's" + document.referrer`, true, "document.referrer"},

		// no sources
		{`x`, false, ""},
		{`"<b>static</b>"`, false, ""},
		{`document.title`, false, ""},
		{`window.names`, false, ""},
		{`document.URLs`, false, ""},
		{`$location`, false, ""},
		{`_location`, false, ""},
		{`location_id`, false, ""},
		{`x.hashes`, false, ""},
		{`x.searchTerm`, false, ""},
		{`$(".search")`, false, ""},
		{`$("#a .hash")`, false, ""},
		{`$("div>.search-box")`, false, ""},
	}

	for _, c := range cases {
		a := NewAnalyzer([]byte(c.js))

		// program > expression_statement > the expression
		n := a.RootNode().NamedChild(0).NamedChild(0)

		tainted, taint := sinkTaint(n)
		if tainted != c.tainted || taint != c.taint {
			t.Errorf("want (%t, %q) for sinkTaint(%s); have (%t, %q)", c.tainted, c.taint, c.js, tainted, taint)
		}
	}

	// invalid nodes must not panic
	if tainted, taint := sinkTaint(nil); tainted || taint != "" {
		t.Errorf("want (false, \"\") for sinkTaint(nil); have (%t, %q)", tainted, taint)
	}
	if tainted, taint := sinkTaint(&Node{}); tainted || taint != "" {
		t.Errorf("want (false, \"\") for sinkTaint(&Node{}); have (%t, %q)", tainted, taint)
	}
}
