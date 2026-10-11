package jsluice

import (
	"testing"
)

func TestMaybeURL(t *testing.T) {
	cases := []struct {
		in       string
		expected bool
	}{
		{"https://example.com", true},
		{"https://example.net/api/v1", true},
		{"HTTP://example.net/api/v1", true},
		{"ws://example.com/socket", true},
		{"wss://example.com/socket", true},
		{"WSS://example.com/socket?token=abc", true},
		{"wss://example.com", true},
		{"ftp://example.com/file.txt", false},
		{"file://example.com/file.txt", false},
		{"application/json", false},
		{"text/plain", false},
		{"//example.org", true},
		{"example.org", false},
		{"foo?id=123", true},
		{"Who? Me?", false},
		{"foo.php?id", true},
		{"foo.lolno?id", false},
		{"/foo/bar.html", true},
		{"./foo/bar.html", true},
		{`~[A-Z](?=[/|([{\u003c\\\"'])`, false},

		// These might look like paths to humans, but we couldn't
		// be confident enough about them programmatically
		{"./", false},
		{"foo/bar", false},
	}

	for _, c := range cases {
		actual := MaybeURL(c.in)
		if actual != c.expected {
			t.Errorf("want %t for MaybeURL(%s); have %t", c.expected, c.in, actual)
		}
	}
}
