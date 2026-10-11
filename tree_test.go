package jsluice

import (
	"strconv"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

func TestCollapsedString(t *testing.T) {
	cases := []struct {
		JS       []byte
		Expected string
	}{
		{[]byte(`"./login.php?redirect="+url`), "./login.php?redirect=EXPR"},
		{[]byte(`'/path/'+['one', 'two', 'three'].join('/')`), "/path/EXPR"},
		{[]byte(`someVar`), "EXPR"},
	}

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	for i, c := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			tree := parser.Parse(nil, c.JS)
			root := NewNode(tree.RootNode(), c.JS)

			// Example tree:
			//   program
			//     expression_statement
			//       binary_expression
			//         left: string ("./login.php?redirect=")
			//         right: identifier (url)
			//
			// We want the binary_expression to pass to CollapsedString, which is
			// the first Named Child of the first Named Child of the root node.
			actual := root.NamedChild(0).NamedChild(0).CollapsedString()

			if actual != c.Expected {
				t.Errorf("want %s for CollapsedString(%s), have: %s", c.Expected, c.JS, actual)
			}
		})
	}
}

func TestCollapsedStringTemplate(t *testing.T) {
	cases := []struct {
		Name string
		JS   string

		// The type of the first node in the source to collapse;
		// defaults to template_string if empty
		NodeType string

		Expected string
	}{
		{
			Name:     "call argument",
			JS:       "fetch(`/api/v2/${id}/x?q=${f(s)}`)",
			Expected: "/api/v2/EXPR/x?q=EXPR",
		},
		{
			Name:     "no substitutions",
			JS:       "fetch(`/static/app.js`)",
			Expected: "/static/app.js",
		},
		{
			Name:     "substitutions at the start and end",
			JS:       "x = `${base}/users/${id}`",
			Expected: "EXPR/users/EXPR",
		},
		{
			Name:     "adjacent substitutions",
			JS:       "x = `${a}${b}`",
			Expected: "EXPREXPR",
		},
		{
			Name:     "only a substitution",
			JS:       "x = `${a}`",
			Expected: "EXPR",
		},
		{
			Name:     "empty template",
			JS:       "x = ``",
			Expected: "",
		},
		{
			Name:     "nested template collapses to one placeholder",
			JS:       "x = `/a/${`b${c}`}/d`",
			Expected: "/a/EXPR/d",
		},
		{
			Name:     "escape sequences are left undecoded",
			JS:       "x = `/a\\n/b${y}`",
			Expected: `/a\n/bEXPR`,
		},
		{
			Name:     "escaped backtick is not the closing backtick",
			JS:       "x = `/a\\`/${y}`",
			Expected: "/a\\`/EXPR",
		},
		{
			Name:     "escaped dollar is not a substitution",
			JS:       "x = `/a/\\${y}`",
			Expected: `/a/\${y}`,
		},
		{
			Name:     "multi-byte characters survive the byte-offset splicing",
			JS:       "x = `/café/${id}/ü中`",
			Expected: "/café/EXPR/ü中",
		},
		{
			Name:     "braces and strings inside the substitution",
			JS:       "x = `/a/${ {b: '}'}.b }/c`",
			Expected: "/a/EXPR/c",
		},
		{
			Name:     "multi-line template",
			JS:       "x = `/a/${id}\n/b`",
			Expected: "/a/EXPR\n/b",
		},
		{
			Name:     "template on the right of a concatenation",
			JS:       "x = '/p/' + `${q}/r`",
			NodeType: "binary_expression",
			Expected: "/p/EXPR/r",
		},
		{
			Name:     "template on the left of a concatenation",
			JS:       "x = `/p/${q}/` + id + '.json'",
			NodeType: "binary_expression",
			Expected: "/p/EXPR/EXPR.json",
		},
	}

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			src := []byte(c.JS)
			tree := parser.Parse(nil, src)
			root := NewNode(tree.RootNode(), src)

			nodeType := c.NodeType
			if nodeType == "" {
				nodeType = "template_string"
			}

			// Matches come back in document order, so the first
			// is the outermost node of the requested type.
			var target *Node
			root.Query("("+nodeType+") @target", func(n *Node) {
				if target == nil {
					target = n
				}
			})

			if target == nil {
				t.Fatalf("no %s node found in %q", nodeType, c.JS)
			}

			actual := target.CollapsedString()
			if actual != c.Expected {
				t.Errorf("want %q for CollapsedString(%q), have: %q", c.Expected, c.JS, actual)
			}
		})
	}
}

func TestCollapsedStringTemplateCustomPlaceholder(t *testing.T) {
	original := ExpressionPlaceholder
	defer func() { ExpressionPlaceholder = original }()
	ExpressionPlaceholder = "{VAR}"

	src := []byte("fetch(`/api/${a}/b/${c}`)")

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	root := NewNode(parser.Parse(nil, src).RootNode(), src)

	var actual string
	root.Query("(template_string) @t", func(n *Node) {
		actual = n.CollapsedString()
	})

	if expected := "/api/{VAR}/b/{VAR}"; actual != expected {
		t.Errorf("want %q with a custom placeholder, have: %q", expected, actual)
	}
}
