package jsluice

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// pmTestListeners runs GetMessageListeners on some JavaScript
func pmTestListeners(js string) []*MessageListener {
	return NewAnalyzer([]byte(js)).GetMessageListeners()
}

// pmTestReceivers returns only the listeners that receive messages
func pmTestReceivers(ls []*MessageListener) []*MessageListener {
	out := make([]*MessageListener, 0)
	for _, l := range ls {
		if l.Kind != pmKindSend {
			out = append(out, l)
		}
	}
	return out
}

// pmTestSameStrings compares two string slices, treating nil as empty
func pmTestSameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGetMessageListeners(t *testing.T) {
	cases := []struct {
		name          string
		js            string
		kind          string
		originChecked bool
		targetOrigin  string
		severity      Severity
		sinks         []string
	}{
		{
			"addEventListener with innerHTML sink",
			`window.addEventListener("message", function(e){ x.innerHTML = e.data; })`,
			"addEventListener", false, "", SeverityHigh, []string{"innerHTML"},
		},
		{
			"addEventListener with origin check",
			`window.addEventListener("message", e => { if (e.origin !== "https://trusted.com") return; handle(e.data); })`,
			"addEventListener", true, "", SeverityLow, nil,
		},
		{
			"onmessage with eval sink",
			`window.onmessage = e => eval(e.data)`,
			"onmessage", false, "", SeverityHigh, []string{"eval("},
		},
		{
			"postMessage to any origin",
			`w.postMessage(data, "*")`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"postMessage to a specific origin",
			`w.postMessage(data, "https://x.com")`,
			pmKindSend, false, "https://x.com", SeverityInfo, nil,
		},
		{
			"addEventListener with no origin check and no sink",
			`window.addEventListener("message", function(e){ handle(e.data); })`,
			"addEventListener", false, "", SeverityMedium, nil,
		},
		{
			"origin checked handler is low even with a sink",
			`window.addEventListener("message", function(e){ if (e.origin === "https://a.example") { x.innerHTML = e.data; } })`,
			"addEventListener", true, "", SeverityLow, []string{"innerHTML"},
		},
		{
			"single quotes",
			`window.addEventListener('message', e => document.write(e.data))`,
			"addEventListener", false, "", SeverityHigh, []string{"document.write"},
		},
		{
			"addEventListener with a third argument",
			`window.addEventListener("message", function(e){ eval(e.data) }, false)`,
			"addEventListener", false, "", SeverityHigh, []string{"eval("},
		},
		{
			"addEventListener without a receiver",
			`addEventListener("message", e => { x.innerHTML = e.data })`,
			"addEventListener", false, "", SeverityHigh, []string{"innerHTML"},
		},
		{
			"computed addEventListener",
			`window["addEventListener"]("message", e => { x.innerHTML = e.data })`,
			"addEventListener", false, "", SeverityHigh, []string{"innerHTML"},
		},
		{
			"self.onmessage",
			`self.onmessage = function(e){ eval(e.data) }`,
			"onmessage", false, "", SeverityHigh, []string{"eval("},
		},
		{
			"bare onmessage",
			`onmessage = function(e){ handle(e.data) }`,
			"onmessage", false, "", SeverityMedium, nil,
		},
		{
			"computed onmessage",
			`window["onmessage"] = function(e){ handle(e.data) }`,
			"onmessage", false, "", SeverityMedium, nil,
		},
		{
			"jQuery on",
			`$(window).on("message", function(e){ $("#a").html(e.originalEvent.data) })`,
			"addEventListener", false, "", SeverityHigh, []string{".html("},
		},
		{
			"jQuery namespaced event on a chain",
			`jQuery(window).off("message").on("message.app", function(e){ if (e.originalEvent.origin !== "https://a.example") return; })`,
			"addEventListener", true, "", SeverityLow, nil,
		},
		{
			"jQuery bind",
			`$(window).bind("resize message", function(e){ handle(e) })`,
			"addEventListener", false, "", SeverityMedium, nil,
		},
		{
			"postMessage with a targetOrigin option",
			`parent.postMessage(secret, {targetOrigin: "*"})`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"postMessage with a specific targetOrigin option",
			`parent.postMessage(secret, {targetOrigin: "https://p.example", transfer: []})`,
			pmKindSend, false, "https://p.example", SeverityInfo, nil,
		},
		{
			"postMessage with a transfer list and a targetOrigin",
			`w.postMessage(data, "*", [buffer])`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"postMessage with a template literal origin",
			"w.postMessage(data, `*`)",
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"postMessage with single quotes and an escape",
			`w.postMessage(data, '\x2a')`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"computed postMessage",
			`w["postMessage"](data, "*")`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"bare postMessage",
			`postMessage(data, "*")`,
			pmKindSend, false, "*", SeverityMedium, nil,
		},
		{
			"optional chaining",
			`a?.b?.postMessage(data, "https://x.example")`,
			pmKindSend, false, "https://x.example", SeverityInfo, nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ls := pmTestListeners(c.js)
			if len(ls) != 1 {
				t.Fatalf("want 1 listener for %s; have %d: %+v", c.js, len(ls), ls)
			}
			l := ls[0]

			if l.Kind != c.kind {
				t.Errorf("want kind %s; have %s", c.kind, l.Kind)
			}
			if l.OriginChecked != c.originChecked {
				t.Errorf("want originChecked %t; have %t", c.originChecked, l.OriginChecked)
			}
			if l.TargetOrigin != c.targetOrigin {
				t.Errorf("want targetOrigin %q; have %q", c.targetOrigin, l.TargetOrigin)
			}
			if l.Severity != c.severity {
				t.Errorf("want severity %s; have %s", c.severity, l.Severity)
			}
			if !pmTestSameStrings(l.Sinks, c.sinks) {
				t.Errorf("want sinks %v; have %v", c.sinks, l.Sinks)
			}
			if l.Line != 1 {
				t.Errorf("want line 1; have %d", l.Line)
			}
			if l.Source == "" {
				t.Error("want a source; have none")
			}
			if l.Filename != "" {
				t.Errorf("want no filename; have %q", l.Filename)
			}
		})
	}
}

func TestGetMessageListenersOriginChecked(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want bool
	}{
		// Handlers that validate the origin
		{"strict inequality", `window.addEventListener("message", e => { if (e.origin !== "https://a.example") return; go(e.data) })`, true},
		{"strict equality", `window.addEventListener("message", e => { if (e.origin === "https://a.example") { go(e.data) } })`, true},
		{"loose comparison", `window.addEventListener("message", e => { if (e.origin != "https://a.example") return; go(e.data) })`, true},
		{"origin on the right", `window.addEventListener("message", e => { if ("https://a.example" !== e.origin) return; go(e.data) })`, true},
		{"compared to location", `window.addEventListener("message", e => { if (e.origin !== window.location.origin) return; go(e.data) })`, true},
		{"parsed origin", `window.addEventListener("message", e => { if (new URL(e.origin).hostname !== "a.example") return; go(e.data) })`, true},
		{"optional chaining", `window.addEventListener("message", e => { if (e?.origin !== "https://a.example") return; go(e.data) })`, true},
		{"computed property", `window.addEventListener("message", e => { if (e["origin"] !== "https://a.example") return; go(e.data) })`, true},
		{"list includes", `window.addEventListener("message", e => { if (!ALLOWED.includes(e.origin)) return; go(e.data) })`, true},
		{"list indexOf", `window.addEventListener("message", e => { if (ALLOWED.indexOf(e.origin) === -1) return; go(e.data) })`, true},
		{"set has", `window.addEventListener("message", e => { if (!ORIGINS.has(e.origin)) return; go(e.data) })`, true},
		{"in operator", `window.addEventListener("message", e => { if (!(e.origin in ALLOWED)) return; go(e.data) })`, true},
		{"lookup", `window.addEventListener("message", e => { if (!ALLOWED[e.origin]) return; go(e.data) })`, true},
		{"switch", `window.addEventListener("message", e => { switch (e.origin) { case "https://a.example": go(e.data); break; default: return; } })`, true},
		{"regex test", `window.addEventListener("message", e => { if (!/^https:\/\/a\.example$/.test(e.origin)) return; go(e.data) })`, true},
		{"origin method", `window.addEventListener("message", e => { if (!e.origin.endsWith(".a.example")) return; go(e.data) })`, true},
		{"origin match", `window.addEventListener("message", e => { if (!e.origin.match(/a\.example$/)) return; go(e.data) })`, true},
		{"helper given the origin", `window.addEventListener("message", e => { if (!isAllowedOrigin(e.origin)) return; go(e.data) })`, true},
		{"method given the origin", `window.addEventListener("message", e => { if (!this.checkOrigin(e.origin)) return; go(e.data) })`, true},
		{"helper given the event", `window.addEventListener("message", e => { if (!isTrusted(e)) return; go(e.data) })`, true},
		{"origin helper given the event", `window.addEventListener("message", e => { if (!checkOrigin(e)) return; go(e.data) })`, true},
		{"same origin helper given the event", `window.addEventListener("message", e => { if (!isSameOrigin(e)) return; go(e.data) })`, true},
		{"different parameter name", `window.addEventListener("message", function(event){ if (event.origin !== "https://a.example") return; go(event.data) })`, true},
		{"minified parameter name", `window.addEventListener("message",function(t){if("https://a.example"!==t.origin)return;go(t.data)})`, true},
		{"alias", `window.addEventListener("message", e => { var o = e.origin; if (o !== "https://a.example") return; go(e.data) })`, true},
		{"derived alias", `window.addEventListener("message", e => { const host = new URL(e.origin).host; if (host !== "a.example") return; go(e.data) })`, true},
		{"destructured declaration", `window.addEventListener("message", e => { const {origin, data} = e; if (origin !== "https://a.example") return; go(data) })`, true},
		{"renamed destructured declaration", `window.addEventListener("message", e => { const {origin: o} = e; if (o !== "https://a.example") return; go(e.data) })`, true},
		{"destructured parameter", `window.addEventListener("message", ({origin, data}) => { if (origin !== "https://a.example") return; go(data) })`, true},
		{"renamed destructured parameter", `window.addEventListener("message", ({origin: o, data}) => { if (o !== "https://a.example") return; go(data) })`, true},
		{"jQuery originalEvent", `$(window).on("message", function(e){ if (e.originalEvent.origin !== "https://a.example") return; go(e.originalEvent.data) })`, true},
		{"jQuery event alias", `$(window).on("message", function(e){ var oe = e.originalEvent || e; if (oe.origin !== "https://a.example") return; go(oe.data) })`, true},
		{"either origin property", `window.addEventListener("message", e => { var o = e.origin || e.originalEvent.origin; if (o !== "https://a.example") return; go(e.data) })`, true},
		{"onmessage", `window.onmessage = function(e){ if (e.origin !== "https://a.example") return; go(e.data) }`, true},
		{"parenthesized handler", `window.addEventListener("message", (function(e){ if (e.origin !== "https://a.example") return; go(e.data) }))`, true},

		// Handlers that do not
		{"no mention of the origin", `window.addEventListener("message", e => { go(e.data) })`, false},
		{"comparison of something else", `window.addEventListener("message", e => { if (e.data.type == "x") go(e.data) })`, false},
		{"origin only logged", `window.addEventListener("message", e => { console.log(e.origin); if (e.data.type == "x") go(e.data) })`, false},
		{"origin only logged with allow word", `window.addEventListener("message", e => { var allowScroll = true; console.log("origin", e.origin); go(e.data) })`, false},
		{"origin of the payload", `window.addEventListener("message", e => { if (e.data.origin === "https://a.example") go(e.data) })`, false},
		{"origin of the parsed payload", `window.addEventListener("message", e => { var d = JSON.parse(e.data); if (d.origin === "https://a.example") go(d) })`, false},
		{"origin of another object", `window.addEventListener("message", e => { if (frame.origin === "https://a.example") go(e.data) })`, false},
		{"own origin", `window.addEventListener("message", e => { if (location.origin === "https://a.example") go(e.data) })`, false},
		{"origin used as the target of a reply", `window.addEventListener("message", e => { e.source.postMessage("ok", e.origin); go(e.data) })`, false},
		{"origin only tested for presence", `window.addEventListener("message", e => { if (e.origin) go(e.data) })`, false},
		{"origin given to a function that sends", `window.addEventListener("message", e => { postToOrigin(e.origin, "ack"); go(e.data) })`, false},
		{"origin given to a function that normalizes", `window.addEventListener("message", e => { normalizeOrigin(e.origin); go(e.data) })`, false},
		{"event given to a function that gets the origin", `window.addEventListener("message", e => { getOrigin(e); go(e.data) })`, false},
		{"event given to a function that sends to the origin", `window.addEventListener("message", e => { replyToOrigin(e); go(e.data) })`, false},
		{"helper not given the origin", `window.addEventListener("message", e => { if (!isAllowed(e.data)) return; go(e.data) })`, false},
		{"validation of the message", `window.addEventListener("message", e => { if (!validate(e)) return; go(e.data) })`, false},
		{"origin in an unrelated function", `function other(e){ if (e.origin !== "x") return; } window.addEventListener("message", function(e){ go(e.data) })`, false},
		{"unresolved handler", `window.addEventListener("message", importedHandler)`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			receivers := pmTestReceivers(pmTestListeners(c.js))
			if len(receivers) != 1 {
				t.Fatalf("want 1 receiver for %s; have %d", c.js, len(receivers))
			}

			if receivers[0].OriginChecked != c.want {
				t.Errorf("want originChecked %t for %s; have %t", c.want, c.js, receivers[0].OriginChecked)
			}

			// low if the origin is checked; otherwise high if the handler
			// has a genuinely dangerous sink (a ".postMessage" reply on its
			// own is not enough), or else medium
			wantSeverity := SeverityLow
			switch {
			case c.want:
			default:
				wantSeverity = SeverityMedium
				for _, s := range receivers[0].Sinks {
					if s != ".postMessage" {
						wantSeverity = SeverityHigh
						break
					}
				}
			}
			if receivers[0].Severity != wantSeverity {
				t.Errorf("want severity %s for %s; have %s", wantSeverity, c.js, receivers[0].Severity)
			}
		})
	}
}

func TestGetMessageListenersChainedAssignment(t *testing.T) {
	// The handler is registered on both objects
	ls := pmTestListeners(`a.onmessage = b.onmessage = function(e){ eval(e.data) }`)
	if len(ls) != 2 {
		t.Fatalf("want 2 listeners; have %d", len(ls))
	}

	for i, l := range ls {
		if l.Kind != "onmessage" || l.Severity != SeverityHigh || !pmTestSameStrings(l.Sinks, []string{"eval("}) {
			t.Errorf("listener %d: want a high onmessage listener with an eval( sink; have %+v", i, l)
		}
	}
}

func TestGetMessageListenersSinks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"innerHTML", `x.innerHTML = e.data`, []string{"innerHTML"}},
		{"outerHTML", `x.outerHTML = e.data`, []string{"outerHTML"}},
		{"document.write", `document.write(e.data)`, []string{"document.write"}},
		{"document.writeln", `document.writeln(e.data)`, []string{"document.write"}},
		{"insertAdjacentHTML", `x.insertAdjacentHTML("beforeend", e.data)`, []string{"insertAdjacentHTML"}},
		{"eval", `eval(e.data)`, []string{"eval("}},
		{"eval of window", `window.eval(e.data)`, []string{"eval("}},
		{"new Function", `new Function(e.data)()`, []string{"new Function"}},
		{"Function", `Function(e.data)()`, []string{"Function("}},
		{"setTimeout of a member", `setTimeout(e.data, 0)`, []string{"setTimeout"}},
		{"setTimeout of a string", `setTimeout("go()", 0)`, []string{"setTimeout"}},
		{"setTimeout of a function", `setTimeout(function(){ go() }, 0)`, nil},
		{"setTimeout of an arrow function", `setTimeout(() => go(), 0)`, nil},
		{"setTimeout of an arrow function with a parameter", `setTimeout(x => go(x), 0)`, nil},
		{"setTimeout of a parenthesized function", `setTimeout((function(){ go() }), 0)`, nil},
		{"setTimeout of an async function", `setTimeout(async () => { await go() }, 0)`, nil},
		{"setTimeout of a name", `setTimeout(go, 0)`, nil},
		{"location assignment", `location = e.data`, []string{"location"}},
		{"location.href assignment", `window.location.href = e.data.url`, []string{"location"}},
		{"document.location assignment", `document.location = e.data`, []string{"location"}},
		{"location.assign", `location.assign(e.data)`, []string{"location"}},
		{"location.replace", `window.location.replace(e.data)`, []string{"location"}},
		{"location read", `var o = location.origin + location.pathname`, nil},
		{"location comparison", `if (location.href == e.data) go()`, nil},
		{"location arrow parameter", `[].map(location => location.id)`, nil},
		{"src assignment", `frame.src = e.data`, []string{".src"}},
		{"html with an argument", `$("#a").html(e.data)`, []string{".html("}},
		{"html getter", `var h = $("#a").html()`, nil},
		{"document.cookie", `document.cookie = e.data`, []string{"document.cookie"}},
		{"document.cookie read", `reply(document.cookie)`, []string{"document.cookie"}},
		{"dangerouslySetInnerHTML", `render({dangerouslySetInnerHTML: {__html: e.data}})`, []string{"dangerouslySetInnerHTML"}},
		{"postMessage reply", `e.source.postMessage(secret, "*")`, []string{".postMessage"}},
		{"several sinks in a fixed order", `eval(e.data); x.innerHTML = e.data; document.cookie = "a=b"`, []string{"innerHTML", "eval(", "document.cookie"}},
		{"nothing dangerous", `go(e.data.value); document.title = "x"; el.textContent = e.data`, nil},
		{"names that contain a sink", `retrieval(e.data); var allocation = relocation(e.data); myFunction(e.data); x.sources = 1; e.source`, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			js := `window.addEventListener("message", function(e){ ` + c.body + ` })`

			receivers := pmTestReceivers(pmTestListeners(js))
			if len(receivers) != 1 {
				t.Fatalf("want 1 receiver for %s; have %d", js, len(receivers))
			}
			l := receivers[0]

			if !pmTestSameStrings(l.Sinks, c.want) {
				t.Errorf("want sinks %v for %s; have %v", c.want, c.body, l.Sinks)
			}

			// A ".postMessage" reply on its own stays medium; a genuinely
			// dangerous sink (eval, innerHTML, ...) raises it to high.
			wantSeverity := SeverityMedium
			for _, s := range c.want {
				if s != ".postMessage" {
					wantSeverity = SeverityHigh
					break
				}
			}
			if l.Severity != wantSeverity {
				t.Errorf("want severity %s for %s; have %s", wantSeverity, c.body, l.Severity)
			}
		})
	}
}

func TestGetMessageListenersResolve(t *testing.T) {
	cases := []struct {
		name string
		js   string

		// the expected result for the one receiver in the JavaScript
		originChecked bool
		sinks         []string

		// whether the handler is found, and so is part of the source
		resolved bool
	}{
		{
			"function declaration after the registration",
			`window.addEventListener("message", onMessage, false);
			function onMessage(e) { x.innerHTML = e.data }`,
			false, []string{"innerHTML"}, true,
		},
		{
			"function declaration with an origin check",
			`window.addEventListener("message", receiveMessage, false);
			function receiveMessage(event) { if (event.origin !== "https://a.example") return; console.log(event.data) }`,
			true, nil, true,
		},
		{
			"arrow function in a const",
			`const onMessage = (event) => { if (!ALLOWED.includes(event.origin)) return; render(event.data) };
			window.addEventListener("message", onMessage);`,
			true, nil, true,
		},
		{
			"function expression in a var",
			`var onMessage = function(e) { eval(e.data) };
			window.addEventListener("message", onMessage);`,
			false, []string{"eval("}, true,
		},
		{
			"exported function",
			`export function onMessage(e) { document.write(e.data) }
			window.addEventListener("message", onMessage);`,
			false, []string{"document.write"}, true,
		},
		{
			"declared and assigned later",
			`var onMessage;
			onMessage = function(e) { eval(e.data) };
			window.addEventListener("message", onMessage);`,
			false, []string{"eval("}, true,
		},
		{
			"assigned in a sequence",
			`var h;h=function(e){eval(e.data)},window.addEventListener("message",h);`,
			false, []string{"eval("}, true,
		},
		{
			"reference to a reference",
			`function onMessage(e) { eval(e.data) }
			var alias = onMessage;
			window.addEventListener("message", alias);`,
			false, []string{"eval("}, true,
		},
		{
			"onmessage assigned a reference",
			`function onMessage(e) { eval(e.data) }
			window.onmessage = onMessage;`,
			false, []string{"eval("}, true,
		},
		{
			"in a closure",
			`(function() {
				function onMessage(e) { if (e.origin !== "https://a.example") return; }
				window.addEventListener("message", onMessage);
			})();`,
			true, nil, true,
		},
		{
			"the nearest definition wins",
			`var t = function(e) { if (e.origin !== "https://a.example") return; };
			function outer() {
				var t = function(e) { document.body.innerHTML = e.data };
				window.addEventListener("message", t);
			}`,
			false, []string{"innerHTML"}, true,
		},
		{
			"a parameter is not a definition",
			`function onMessage(e) { eval(e.data) }
			function listen(onMessage) { window.addEventListener("message", onMessage) }`,
			false, nil, false,
		},
		{
			"not defined in the file",
			`window.addEventListener("message", importedHandler);`,
			false, nil, false,
		},
		{
			"class method with bind",
			`class Widget {
				constructor() { window.addEventListener("message", this.receive.bind(this)); }
				receive(e) { if (e.origin === "https://a.example") { this.x.innerHTML = e.data } }
			}`,
			true, []string{"innerHTML"}, true,
		},
		{
			"class method without bind",
			`class Widget {
				start() { window.addEventListener("message", this.receive); }
				receive(e) { eval(e.data) }
			}`,
			false, []string{"eval("}, true,
		},
		{
			"class field",
			`class Widget extends Base {
				handle = (e) => { this.x.innerHTML = e.data };
				componentDidMount() { window.addEventListener("message", this.handle); }
			}`,
			false, []string{"innerHTML"}, true,
		},
		{
			"bound in the constructor",
			`class Widget {
				constructor() { this._bound = this._onMessage.bind(this); }
				start() { window.addEventListener("message", this._bound); }
				_onMessage(e) { if (e.origin !== "https://a.example") return; }
			}`,
			true, nil, true,
		},
		{
			"library bind",
			`function Widget() {
				this._relay = function(e) { document.body.innerHTML = e.data };
				window.addEventListener("message", _.bind(this._relay, this));
			}`,
			false, []string{"innerHTML"}, true,
		},
		{
			"assigned in a constructor function",
			`function Widget() {
				this.h = function(e) { eval(e.data) };
				window.addEventListener("message", this.h);
			}`,
			false, []string{"eval("}, true,
		},
		{
			"method of an object literal",
			`var widget = {
				init: function() { window.addEventListener("message", this.onMsg); },
				onMsg: function(e) { location = e.data }
			};`,
			false, []string{"location"}, true,
		},
		{
			"only function with that property name",
			`var handlers = { onlyOne: function(e) { document.write(e.data) } };
			window.addEventListener("message", app.handlers.onlyOne);`,
			false, []string{"document.write"}, true,
		},
		{
			"property name that is ambiguous",
			`var o1 = { run: function(e) { a.innerHTML = e.data } };
			var o2 = { run: function(e) { if (e.origin !== "x") return } };
			window.addEventListener("message", something.run);`,
			false, nil, false,
		},
		{
			"wrapped inline function",
			`window.addEventListener("message", debounce(function(e) { x.innerHTML = e.data }, 100));`,
			false, []string{"innerHTML"}, false,
		},
		{
			"wrapped reference",
			`function onMessage(e) { x.innerHTML = e.data }
			window.addEventListener("message", debounce(onMessage, 100));`,
			false, []string{"innerHTML"}, true,
		},
		{
			// The callback can not be using the event, so any origin it compares
			// is not the origin of the message
			"callback of a handler factory is not the handler",
			`window.addEventListener("message", makeHandler(config, function() { if (config.origin !== "https://a.example") return; }));`,
			false, nil, false,
		},
		{
			"references that refer to each other",
			`var a = b, b = a;
			window.addEventListener("message", a);`,
			false, nil, false,
		},
		{
			"a handler that binds itself",
			`this.h = this.h.bind(this);
			window.addEventListener("message", this.h);`,
			false, nil, false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			receivers := pmTestReceivers(pmTestListeners(c.js))
			if len(receivers) != 1 {
				t.Fatalf("want 1 receiver for %s; have %d", c.js, len(receivers))
			}
			l := receivers[0]

			if l.OriginChecked != c.originChecked {
				t.Errorf("want originChecked %t; have %t", c.originChecked, l.OriginChecked)
			}
			if !pmTestSameStrings(l.Sinks, c.sinks) {
				t.Errorf("want sinks %v; have %v", c.sinks, l.Sinks)
			}

			// A handler that is found somewhere else in the file is added to the
			// source after the registration, on a line of its own
			if hasHandler := strings.Contains(l.Source, "\n"); hasHandler != c.resolved {
				t.Errorf("want handler included in source to be %t; have %t: %q", c.resolved, hasHandler, l.Source)
			}
		})
	}
}

func TestGetMessageListenersNone(t *testing.T) {
	cases := []struct {
		name string
		js   string
	}{
		{"empty", ``},
		{"no messaging", `var a = 1; function f() { return a }`},
		{"other event", `window.addEventListener("click", function(e){ x.innerHTML = e.target.value })`},
		{"similar event", `window.addEventListener("messageerror", function(e){ x.innerHTML = e.data })`},
		{"dynamic event", `window.addEventListener(name, function(e){ x.innerHTML = e.data })`},
		{"no handler", `window.addEventListener("message")`},
		{"removed listener", `window.removeEventListener("message", handler)`},
		{"cleared onmessage", `ws.onmessage = null`},
		{"undefined onmessage", `ws.onmessage = undefined`},
		{"void onmessage", `ws.onmessage = void 0`},
		{"other property", `ws.onopen = function(e){ eval(e.data) }`},
		{"declared onmessage", `var onmessage = 1`},
		{"augmented assignment", `ws.onmessage ||= handler`},
		{"jQuery on another element", `$(el).on("message", function(e){ eval(e.data) })`},
		{"jQuery on another event", `$(window).on("resize", function(e){ eval(e.data) })`},
		{"other emitter", `emitter.on("message", function(e){ eval(e.data) })`},
		{"bind", `var f = handler.bind(this)`},
		{"Worker without a target origin", `worker.postMessage(data)`},
		{"Worker with a transfer list", `worker.postMessage(data, [buffer])`},
		{"options without a target origin", `w.postMessage(data, {transfer: [buffer]})`},
		{"variable target origin", `w.postMessage(data, targetOrigin)`},
		{"built target origin", `w.postMessage(data, "https://" + host)`},
		{"template with a substitution", "w.postMessage(data, `https://${host}`)"},
		{"no arguments", `w.postMessage()`},
		{"tagged template", "postMessage`abc`"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ls := pmTestListeners(c.js)
			if len(ls) != 0 {
				t.Errorf("want no listeners for %s; have %d: %+v", c.js, len(ls), ls[0])
			}
		})
	}
}

func TestGetMessageListenersNotNil(t *testing.T) {
	// An empty slice and not nil is easier to deal with, e.g. when using jq
	ls := pmTestListeners(`var a = 1`)
	if ls == nil {
		t.Fatal("want an empty slice; have nil")
	}
	if len(ls) != 0 {
		t.Errorf("want 0 listeners; have %d", len(ls))
	}

	b, err := json.Marshal(ls)
	if err != nil {
		t.Fatalf("want nil error for json.Marshal; have %s", err)
	}
	if string(b) != "[]" {
		t.Errorf("want [] for no listeners; have %s", b)
	}
}

func TestGetMessageListenersNeverPanics(t *testing.T) {
	cases := []string{
		"",
		" \n\t ",
		"\x00\x01\x02 garbage \xff\xfe",
		`window.addEventListener("message", function(e){ if (e.origin ((( x.innerHTML = e.data ;;; }}} `,
		`window.addEventListener("message", `,
		`window.addEventListener(`,
		`window.onmessage =`,
		`.postMessage(a, "*")`,
		`w.postMessage(,"*")`,
		`$(window).on("message"`,
		`class { constructor() { window.addEventListener("message", this.`,
		`window.addEventListener("message", function(`,
		`window.addEventListener("message", ({origin, ...rest}, [a, b], c = 1) => {});`,
		`window.addEventListener("message", async function*(e) { yield e.origin })`,
		`window.addEventListener("message", /* c */ handler /* d */, /* e */ false)`,
		`function f(/* e */ e, ...a) { if (e.origin === 1) {} } window.addEventListener("message", f)`,
	}

	for i, js := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panic for %q: %v", i, js, r)
				}
			}()
			pmTestListeners(js)
		}()
	}
}

func TestGetMessageListenersMultiple(t *testing.T) {
	js := `
// first
window.addEventListener("message", function(e) {
	e.source.postMessage({ok: true}, "*");
	x.innerHTML = e.data;
});

var other = 1;

window.onmessage = function(e) {
	if (e.origin !== "https://a.example") return;
};

parent.postMessage("ready", "https://b.example");
`

	ls := pmTestListeners(js)

	want := []struct {
		kind     string
		line     int
		severity Severity
	}{
		{"addEventListener", 3, SeverityHigh},
		{pmKindSend, 4, SeverityMedium},
		{"onmessage", 10, SeverityLow},
		{pmKindSend, 14, SeverityInfo},
	}

	if len(ls) != len(want) {
		t.Fatalf("want %d listeners; have %d: %+v", len(want), len(ls), ls)
	}

	for i, w := range want {
		if ls[i].Kind != w.kind || ls[i].Line != w.line || ls[i].Severity != w.severity {
			t.Errorf(
				"listener %d: want %s on line %d with severity %s; have %s on line %d with severity %s",
				i, w.kind, w.line, w.severity, ls[i].Kind, ls[i].Line, ls[i].Severity,
			)
		}
	}

	// The reply to the sender is a sink of the handler that it is in
	if !pmTestSameStrings(ls[0].Sinks, []string{"innerHTML", ".postMessage"}) {
		t.Errorf("want sinks [innerHTML .postMessage]; have %v", ls[0].Sinks)
	}
}

func TestGetMessageListenersSource(t *testing.T) {
	t.Run("short source is not truncated", func(t *testing.T) {
		js := `window.addEventListener("message", function(e){ x.innerHTML = e.data; })`

		ls := pmTestListeners(js)
		if len(ls) != 1 {
			t.Fatalf("want 1 listener; have %d", len(ls))
		}
		if ls[0].Source != js {
			t.Errorf("want source %q; have %q", js, ls[0].Source)
		}
	})

	t.Run("long source is truncated", func(t *testing.T) {
		js := `window.addEventListener("message", function(e){ x.innerHTML = e.data; var a = "` +
			strings.Repeat("a", 2000) + `"; })`

		ls := pmTestListeners(js)
		if len(ls) != 1 {
			t.Fatalf("want 1 listener; have %d", len(ls))
		}
		if len(ls[0].Source) > pmMaxSource+len("...") {
			t.Errorf("want source of at most %d bytes; have %d", pmMaxSource+len("..."), len(ls[0].Source))
		}
		if !strings.HasSuffix(ls[0].Source, "...") {
			t.Errorf("want truncated source to end with ...; have %q", ls[0].Source[len(ls[0].Source)-10:])
		}
		if !strings.HasPrefix(ls[0].Source, `window.addEventListener("message"`) {
			t.Errorf("want source to start with the registration; have %q", ls[0].Source[:40])
		}

		// the whole handler is still analyzed
		if !pmTestSameStrings(ls[0].Sinks, []string{"innerHTML"}) {
			t.Errorf("want sinks [innerHTML]; have %v", ls[0].Sinks)
		}
	})

	t.Run("truncation does not split a character", func(t *testing.T) {
		// Try every alignment of a three byte character at the cut
		for pad := 0; pad < 4; pad++ {
			js := `w.postMessage("` + strings.Repeat("a", 440+pad) + strings.Repeat("日", 100) + `", "*")`

			ls := pmTestListeners(js)
			if len(ls) != 1 {
				t.Fatalf("want 1 listener; have %d", len(ls))
			}
			if !utf8.ValidString(ls[0].Source) {
				t.Errorf("pad %d: want valid UTF-8 in source; have %q", pad, ls[0].Source)
			}
			if !strings.HasSuffix(ls[0].Source, "...") {
				t.Errorf("pad %d: want truncated source to end with ...", pad)
			}
		}
	})

	t.Run("handler elsewhere in the file is included", func(t *testing.T) {
		js := `window.addEventListener("message", onMessage);

function onMessage(e) { eval(e.data) }`

		ls := pmTestListeners(js)
		if len(ls) != 1 {
			t.Fatalf("want 1 listener; have %d", len(ls))
		}

		want := "window.addEventListener(\"message\", onMessage)\nfunction onMessage(e) { eval(e.data) }"
		if ls[0].Source != want {
			t.Errorf("want source %q; have %q", want, ls[0].Source)
		}
		if ls[0].Line != 1 {
			t.Errorf("want line of the registration, 1; have %d", ls[0].Line)
		}
	})
}

func TestGetMessageListenersHTML(t *testing.T) {
	js := `<!doctype html>
<html>
<body>
<p>hello</p>
<script>
window.onmessage = e => eval(e.data)
</script>
</body>
</html>`

	ls := pmTestListeners(js)
	if len(ls) != 1 {
		t.Fatalf("want 1 listener; have %d", len(ls))
	}

	if ls[0].Kind != "onmessage" || ls[0].Severity != SeverityHigh {
		t.Errorf("want a high onmessage listener; have %s %s", ls[0].Severity, ls[0].Kind)
	}
}

func TestMessageListenerJSON(t *testing.T) {
	cases := []struct {
		name     string
		listener *MessageListener
		want     map[string]any
		absent   []string
	}{
		{
			"receiver",
			&MessageListener{
				Kind:     "addEventListener",
				Severity: SeverityHigh,
				Sinks:    []string{"innerHTML"},
				Line:     3,
				Source:   "src",
				Filename: "a.js",
			},
			map[string]any{
				"kind":          "addEventListener",
				"originChecked": false,
				"severity":      "high",
				"sinks":         []any{"innerHTML"},
				"line":          float64(3),
				"source":        "src",
				"filename":      "a.js",
			},
			[]string{"targetOrigin"},
		},
		{
			"sender",
			&MessageListener{
				Kind:         pmKindSend,
				TargetOrigin: "*",
				Severity:     SeverityMedium,
				Line:         1,
				Source:       "src",
			},
			map[string]any{
				"kind":          "postMessageSend",
				"originChecked": false,
				"targetOrigin":  "*",
				"severity":      "medium",
				"line":          float64(1),
				"source":        "src",
			},
			[]string{"sinks", "filename"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := json.Marshal(c.listener)
			if err != nil {
				t.Fatalf("want nil error for json.Marshal; have %s", err)
			}

			var got map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("want nil error for json.Unmarshal; have %s", err)
			}

			for k, want := range c.want {
				have, exists := got[k]
				if !exists {
					t.Errorf("want key %s in %s", k, b)
					continue
				}

				wantJSON, _ := json.Marshal(want)
				haveJSON, _ := json.Marshal(have)
				if string(wantJSON) != string(haveJSON) {
					t.Errorf("want %s to be %s; have %s", k, wantJSON, haveJSON)
				}
			}

			for _, k := range c.absent {
				if _, exists := got[k]; exists {
					t.Errorf("want no key %s in %s", k, b)
				}
			}

			if len(got) != len(c.want) {
				t.Errorf("want %d keys; have %d: %s", len(c.want), len(got), b)
			}
		})
	}
}
