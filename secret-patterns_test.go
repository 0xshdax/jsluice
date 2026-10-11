package jsluice

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const (
	secpatHex     = "0123456789abcdef"
	secpatUpper   = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	secpatAlnum   = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	secpatURLSafe = secpatAlnum + "-_"
	secpatBase64  = secpatAlnum + "+/"
)

// secpatGen returns a deterministic pseudo-random string of n characters drawn
// from alphabet. The sample secrets in these tests are built with it rather
// than written out as literals, so the repository never contains anything
// that looks like a real credential to a secret scanner.
func secpatGen(seed uint32, n int, alphabet string) string {
	out := make([]byte, n)
	x := seed
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = alphabet[(x>>16)%uint32(len(alphabet))]
	}
	return string(out)
}

// secpatPEM builds a PEM-style block with three lines of body. The headers
// (if any) come straight after the BEGIN line, and sep goes between lines.
func secpatPEM(label string, headers []string, seed uint32, sep string) string {
	var b strings.Builder

	b.WriteString("-----BEGIN " + label + "-----" + sep)
	if len(headers) > 0 {
		for _, h := range headers {
			b.WriteString(h + sep)
		}
		b.WriteString(sep)
	}
	for i := uint32(0); i < 3; i++ {
		b.WriteString(secpatGen(seed+i, 64, secpatBase64) + sep)
	}
	b.WriteString("-----END " + label + "-----" + sep)

	return b.String()
}

// secpatScan returns the secrets found in src by patternSecretMatcher, and
// only by that matcher. Every other matcher is ignored, and so are the
// duplicates that appear once patternSecretMatcher has also been added to
// AllSecretMatchers(), so the tests are not sensitive to whether it has been.
func secpatScan(src string) []*Secret {
	a := NewAnalyzer([]byte(src))
	a.AddSecretMatcher(patternSecretMatcher())

	seen := make(map[string]bool)
	out := make([]*Secret, 0)

	for _, s := range a.GetSecrets() {
		data, ok := s.Data.(map[string]string)
		if !ok || data["pattern"] == "" {
			continue
		}

		id := s.Kind + "\x00" + data["match"]
		if seen[id] {
			continue
		}
		seen[id] = true

		out = append(out, s)
	}
	return out
}

type secpatCase struct {
	name     string
	kind     string
	severity Severity

	// value is the contents of the string literal exactly as it is
	// written in the JavaScript source (i.e. escape sequences intact)
	value string

	// match is the expected Data["match"]; if empty it is the same as value
	match string
}

func secpatPositiveCases() []secpatCase {
	b64 := base64.RawURLEncoding.EncodeToString
	g := secpatGen

	jwtHeader := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	jwtPayload := b64([]byte(`{"sub":"1234567890","role":"user","iat":1700000000}`))
	mapboxPayload := b64([]byte(`{"u":"acme","a":"cl9abc123xyz456"}`))

	ghs := "ghs_" + g(2, 36, secpatAlnum)
	stripe := "sk_live_" + g(11, 32, secpatAlnum)
	slackHook := "https://hooks.slack.com/services/T" + g(8, 8, secpatUpper) + "/B" + g(9, 8, secpatUpper) + "/" + g(10, 24, secpatAlnum)

	cases := []secpatCase{
		{"privateKey/rsa", "privateKey", SeverityHigh, secpatPEM("RSA PRIVATE KEY", nil, 100, `\n`), secpatPEM("RSA PRIVATE KEY", nil, 100, "\n")},
		{"privateKey/pkcs8", "privateKey", SeverityHigh, secpatPEM("PRIVATE KEY", nil, 110, `\n`), secpatPEM("PRIVATE KEY", nil, 110, "\n")},
		{"privateKey/ec", "privateKey", SeverityHigh, secpatPEM("EC PRIVATE KEY", nil, 120, `\r\n`), secpatPEM("EC PRIVATE KEY", nil, 120, "\r\n")},
		{"privateKey/dsa", "privateKey", SeverityHigh, secpatPEM("DSA PRIVATE KEY", nil, 130, `\n`), secpatPEM("DSA PRIVATE KEY", nil, 130, "\n")},
		{"privateKey/openssh", "privateKey", SeverityHigh, secpatPEM("OPENSSH PRIVATE KEY", nil, 140, `\n`), secpatPEM("OPENSSH PRIVATE KEY", nil, 140, "\n")},
		{"privateKey/encrypted pkcs8", "privateKey", SeverityHigh, secpatPEM("ENCRYPTED PRIVATE KEY", nil, 150, `\n`), secpatPEM("ENCRYPTED PRIVATE KEY", nil, 150, "\n")},
		{
			"privateKey/pgp with armor headers", "privateKey", SeverityHigh,
			secpatPEM("PGP PRIVATE KEY BLOCK", []string{"Version: GnuPG v2", "Comment: test"}, 160, `\n`),
			secpatPEM("PGP PRIVATE KEY BLOCK", []string{"Version: GnuPG v2", "Comment: test"}, 160, "\n"),
		},
		{
			"privateKey/encrypted rsa with Proc-Type headers", "privateKey", SeverityHigh,
			secpatPEM("RSA PRIVATE KEY", []string{"Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC," + g(170, 32, "0123456789ABCDEF")}, 171, `\n`),
			secpatPEM("RSA PRIVATE KEY", []string{"Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC," + g(170, 32, "0123456789ABCDEF")}, 171, "\n"),
		},

		{"githubToken/server", "githubToken", SeverityHigh, ghs, ""},
		{"githubToken/oauth", "githubToken", SeverityHigh, "gho_" + g(3, 36, secpatAlnum), ""},
		{"githubToken/fine-grained", "githubToken", SeverityHigh, "github_pat_" + g(4, 22, secpatAlnum) + "_" + g(5, 59, secpatAlnum), ""},
		{"githubToken/in header", "githubToken", SeverityHigh, "Authorization: Bearer " + ghs, ""},
		{"githubToken/beats basicAuthUrl", "githubToken", SeverityHigh, "https://x-access-token:" + ghs + "@github.com/example/repo.git", ""},
		{"gitlabToken", "gitlabToken", SeverityHigh, "glpat-" + g(6, 20, secpatURLSafe), ""},

		{"slackToken/bot", "slackToken", SeverityHigh, "xoxb-123456789012-1234567890123-" + g(7, 24, secpatAlnum), ""},
		{"slackToken/user", "slackToken", SeverityHigh, "xoxp-123456789012-123456789012-1234567890123-" + g(12, 32, secpatHex), ""},
		{"slackToken/rotating", "slackToken", SeverityHigh, "xoxe.xoxp-1-" + g(13, 120, secpatURLSafe), ""},
		{"slackWebhook", "slackWebhook", SeverityHigh, slackHook, ""},
		{"slackWebhook/json escaped slashes", "slackWebhook", SeverityHigh, strings.ReplaceAll(slackHook, "/", `\/`), slackHook},

		{"stripeSecretKey", "stripeSecretKey", SeverityHigh, stripe, ""},
		{"stripeSecretKey/restricted", "stripeSecretKey", SeverityHigh, "rk_live_" + g(14, 32, secpatAlnum), ""},
		{"stripeSecretKey/after an escaped newline", "stripeSecretKey", SeverityHigh, `NODE_ENV=production\nSTRIPE_KEY=` + stripe + `\nDEBUG=0`, "NODE_ENV=production\nSTRIPE_KEY=" + stripe + "\nDEBUG=0"},
		{"stripeTestKey", "stripeTestKey", SeverityLow, "sk_test_" + g(15, 32, secpatAlnum), ""},
		{"stripePublishableKey", "stripePublishableKey", SeverityInfo, "pk_live_" + g(16, 32, secpatAlnum), ""},

		{"googleOAuthClientSecret", "googleOAuthClientSecret", SeverityHigh, "GOCSPX-" + g(17, 28, secpatURLSafe), ""},
		{"googleOAuthToken", "googleOAuthToken", SeverityMedium, "ya29.a0" + g(18, 120, secpatURLSafe), ""},

		{"sendgridKey", "sendgridKey", SeverityHigh, "SG." + g(19, 22, secpatURLSafe) + "." + g(20, 43, secpatURLSafe), ""},
		{"twilioApiKey", "twilioApiKey", SeverityMedium, "SK" + g(21, 32, secpatHex), ""},
		{"twilioAccountSid", "twilioAccountSid", SeverityLow, "AC" + g(22, 32, secpatHex), ""},
		{"mailgunKey", "mailgunKey", SeverityMedium, "key-" + g(23, 32, secpatHex), ""},
		{"mailchimpKey", "mailchimpKey", SeverityMedium, g(24, 32, secpatHex) + "-us14", ""},

		{"npmToken", "npmToken", SeverityHigh, "npm_" + g(25, 36, secpatAlnum), ""},
		{"shopifyToken", "shopifyToken", SeverityHigh, "shpat_" + g(26, 32, secpatHex), ""},
		{"shopifyToken/shared secret", "shopifyToken", SeverityHigh, "shpss_" + g(27, 32, secpatHex), ""},
		{"squareAccessToken", "squareAccessToken", SeverityHigh, "sq0atp-" + g(28, 22, secpatURLSafe), ""},
		{"squareOAuthSecret", "squareOAuthSecret", SeverityHigh, "sq0csp-" + g(29, 43, secpatURLSafe), ""},
		{"squareToken", "squareToken", SeverityHigh, "EAAA" + g(30, 60, secpatURLSafe), ""},

		{"digitaloceanToken", "digitaloceanToken", SeverityHigh, "dop_v1_" + g(31, 64, secpatHex), ""},
		{"mapboxSecretToken", "mapboxSecretToken", SeverityHigh, "sk." + mapboxPayload + "." + g(32, 22, secpatURLSafe), ""},
		{"mapboxPublicToken", "mapboxPublicToken", SeverityInfo, "pk." + mapboxPayload + "." + g(33, 22, secpatURLSafe), ""},

		{"openaiKey/project", "openaiKey", SeverityHigh, "sk-proj-" + g(34, 48, secpatURLSafe), ""},
		{"openaiKey/legacy", "openaiKey", SeverityHigh, "sk-" + g(35, 20, secpatAlnum) + "T3BlbkFJ" + g(36, 20, secpatAlnum), ""},
		{"anthropicKey", "anthropicKey", SeverityHigh, "sk-ant-api03-" + g(37, 93, secpatURLSafe) + "AA", ""},
		{"huggingfaceToken", "huggingfaceToken", SeverityHigh, "hf_" + g(38, 34, secpatAlnum), ""},

		{"postmanKey", "postmanKey", SeverityHigh, "PMAK-" + g(39, 24, secpatHex) + "-" + g(40, 34, secpatHex), ""},
		{"figmaToken", "figmaToken", SeverityHigh, "figd_" + g(41, 40, secpatURLSafe), ""},
		{"linearKey", "linearKey", SeverityHigh, "lin_api_" + g(42, 40, secpatAlnum), ""},
		{"notionToken/legacy", "notionToken", SeverityHigh, "secret_" + g(43, 43, secpatAlnum), ""},
		{"notionToken/ntn", "notionToken", SeverityHigh, "ntn_" + g(44, 46, secpatAlnum), ""},
		{"atlassianToken", "atlassianToken", SeverityHigh, "ATATT3xFfGF0" + g(45, 150, secpatURLSafe) + "=" + g(46, 8, "0123456789ABCDEF"), ""},
		{"databricksToken", "databricksToken", SeverityHigh, "dapi" + g(47, 32, secpatHex), ""},
		{"databricksToken/numbered", "databricksToken", SeverityHigh, "dapi" + g(48, 32, secpatHex) + "-2", ""},
		{"newRelicKey", "newRelicKey", SeverityHigh, "NRAK-" + g(49, 27, secpatUpper), ""},
		{"dropboxToken", "dropboxToken", SeverityMedium, "sl." + g(50, 140, secpatURLSafe), ""},

		{"telegramBotToken", "telegramBotToken", SeverityHigh, "1234567890:AA" + g(51, 33, secpatURLSafe), ""},
		{"telegramBotToken/in api url", "telegramBotToken", SeverityHigh, "https://api.telegram.org/bot123456789:AA" + g(52, 33, secpatURLSafe) + "/getMe", ""},
		{"discordWebhook", "discordWebhook", SeverityHigh, "https://discord.com/api/webhooks/123456789012345678/" + g(53, 68, secpatURLSafe), ""},
		{"discordWebhook/discordapp", "discordWebhook", SeverityHigh, "https://canary.discordapp.com/api/v10/webhooks/123456789012345678/" + g(54, 68, secpatURLSafe), ""},
		{"sentryDsn", "sentryDsn", SeverityMedium, "https://" + g(55, 32, secpatHex) + "@o4504321.ingest.sentry.io/4504322", ""},
		{"sentryDsn/regional", "sentryDsn", SeverityMedium, "https://" + g(56, 32, secpatHex) + "@o4504321.ingest.us.sentry.io/4504322", ""},
		{"sentryDsn/legacy", "sentryDsn", SeverityMedium, "https://" + g(57, 32, secpatHex) + "@sentry.io/1234567", ""},

		{"jwt", "jwt", SeverityLow, jwtHeader + "." + jwtPayload + "." + g(58, 43, secpatURLSafe), ""},
		{"basicAuthUrl", "basicAuthUrl", SeverityMedium, "https://admin:Sup3rS3cret@internal.example.com/api", ""},
		{"dbConnectionString/postgres", "dbConnectionString", SeverityHigh, "postgres://app:hunter2hunter2@db.internal.example.com:5432/app", ""},
		{"dbConnectionString/mongodb srv", "dbConnectionString", SeverityHigh, "mongodb+srv://app:p%40ssw0rd@cluster0.example.net/app", ""},
		{"dbConnectionString/redis without a user", "dbConnectionString", SeverityHigh, "redis://:s3cretpassw0rd@cache.example.com:6379/0", ""},
		{"dbConnectionString/tls redis", "dbConnectionString", SeverityHigh, "rediss://default:s3cretpassw0rd@cache.example.com:6380", ""},
	}

	for i := range cases {
		if cases[i].match == "" {
			cases[i].match = cases[i].value
		}
	}
	return cases
}

func TestPatternSecretMatcherPositives(t *testing.T) {
	for _, c := range secpatPositiveCases() {
		for _, quote := range []string{`"`, `'`} {
			name := c.name + "/" + quote

			t.Run(name, func(t *testing.T) {
				secrets := secpatScan(fmt.Sprintf("var k = %s%s%s;", quote, c.value, quote))

				if len(secrets) != 1 {
					t.Fatalf("want exactly 1 secret for %s; have %d: %+v", c.name, len(secrets), secrets)
				}

				s := secrets[0]
				if s.Kind != c.kind {
					t.Errorf("want kind %q for %s; have %q", c.kind, c.name, s.Kind)
				}
				if s.Severity != c.severity {
					t.Errorf("want severity %q for %s; have %q", c.severity, c.name, s.Severity)
				}

				data := s.Data.(map[string]string)
				if data["pattern"] != c.kind {
					t.Errorf("want pattern %q for %s; have %q", c.kind, c.name, data["pattern"])
				}
				if data["match"] != c.match {
					t.Errorf("want match %q for %s; have %q", c.match, c.name, data["match"])
				}

				if s.Context != nil {
					t.Errorf("want nil context for a string that isn't in an object; have %v", s.Context)
				}
			})
		}
	}
}

func TestPatternSecretMatcherCoversEveryRule(t *testing.T) {
	covered := make(map[string]bool)
	for _, c := range secpatPositiveCases() {
		covered[c.kind] = true
	}

	for _, r := range secpatRules {
		if !covered[r.name] {
			t.Errorf("rule %q has no positive test case", r.name)
		}
	}
}

func TestPatternSecretMatcherNegatives(t *testing.T) {
	g := secpatGen
	b64 := base64.RawURLEncoding.EncodeToString

	jwtHeader := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	jwtPayload := b64([]byte(`{"sub":"1234567890","role":"user","iat":1700000000}`))
	body := secpatPEM("PUBLIC KEY", nil, 200, `\n`)

	cases := []struct {
		name  string
		value string
	}{
		{"privateKey/bare header", "-----BEGIN RSA PRIVATE KEY-----"},
		{"privateKey/header and footer only", `-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----`},
		{"privateKey/format string", `-----BEGIN ` + "%s" + ` PRIVATE KEY-----\n` + "%s" + `\n-----END PRIVATE KEY-----`},
		{"privateKey/public key", body},
		{"privateKey/certificate", strings.ReplaceAll(body, "PUBLIC KEY", "CERTIFICATE")},

		{"githubToken/too short", "ghs_" + g(1, 35, secpatAlnum)},
		{"githubToken/glued onto an identifier", "xghs_" + g(2, 36, secpatAlnum)},
		{"gitlabToken/too short", "glpat-" + g(3, 19, secpatURLSafe)},

		{"slackToken/placeholder", "xoxb-your-bot-token-here"},
		{"slackToken/too short", "xoxb-12345"},
		{"slackWebhook/placeholder", "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX"},

		{"stripeSecretKey/too short", "sk_live_" + g(4, 23, secpatAlnum)},
		{"stripeSecretKey/glued onto an identifier", "my_sk_live_" + g(5, 32, secpatAlnum)},
		{"stripeTestKey/too short", "sk_test_" + g(6, 23, secpatAlnum)},
		{"stripePublishableKey/too short", "pk_live_" + g(7, 23, secpatAlnum)},

		{"googleOAuthClientSecret/too short", "GOCSPX-" + g(8, 27, secpatURLSafe)},
		{"googleOAuthToken/too short", "ya29." + g(9, 20, secpatURLSafe)},
		{"sendgridKey/wrong segment length", "SG." + g(10, 21, secpatURLSafe) + "." + g(11, 43, secpatURLSafe)},

		{"twilioApiKey/too short", "SK" + g(12, 31, secpatHex)},
		{"twilioAccountSid/too short", "AC" + g(13, 31, secpatHex)},
		{"twilioAccountSid/not hex", "AC" + g(14, 32, "ghijklmnopqrstuv")},
		{"twilioAccountSid/longer hash", "AC" + g(15, 40, secpatHex)},
		{"mailgunKey/part of another name", "cache-key-" + g(16, 32, secpatHex)},
		{"mailgunKey/public validation key", "pubkey-" + g(17, 32, secpatHex)},
		{"mailchimpKey/no datacentre", g(18, 32, secpatHex) + "-us"},
		{"mailchimpKey/too short", g(19, 31, secpatHex) + "-us14"},

		{"npmToken/too short", "npm_" + g(20, 35, secpatAlnum)},
		{"npmToken/environment variable", "npm_config_user_agent_and_some_more_words"},
		{"shopifyToken/too short", "shpat_" + g(21, 31, secpatHex)},
		{"squareAccessToken/too short", "sq0atp-" + g(22, 21, secpatURLSafe)},
		{"squareOAuthSecret/too short", "sq0csp-" + g(23, 42, secpatURLSafe)},
		{"squareToken/too short", "EAAA" + g(24, 59, secpatURLSafe)},
		{"squareToken/longer than a square token", "EAAA" + g(25, 180, secpatURLSafe)},
		{"squareToken/base64 blob", "EAAA" + g(26, 30, secpatURLSafe) + "+" + g(27, 40, secpatURLSafe)},

		{"digitaloceanToken/too short", "dop_v1_" + g(28, 63, secpatHex)},
		{"mapboxSecretToken/too short", "sk.eyJ" + g(29, 10, secpatURLSafe) + "." + g(30, 5, secpatURLSafe)},
		{"mapboxPublicToken/too short", "pk.eyJ" + g(31, 10, secpatURLSafe) + "." + g(32, 5, secpatURLSafe)},

		{"openaiKey/too short", "sk-proj-" + g(33, 10, secpatURLSafe)},
		{"openaiKey/no marker", "sk-" + g(34, 40, secpatAlnum)},
		{"anthropicKey/too short", "sk-ant-" + g(35, 10, secpatURLSafe)},
		{"huggingfaceToken/too short", "hf_" + g(36, 33, secpatAlnum)},

		{"postmanKey/wrong segment length", "PMAK-" + g(37, 23, secpatHex) + "-" + g(38, 34, secpatHex)},
		{"figmaToken/too short", "figd_" + g(39, 39, secpatURLSafe)},
		{"linearKey/too short", "lin_api_" + g(40, 39, secpatAlnum)},
		{"notionToken/client secret", "client_secret_" + g(41, 43, secpatAlnum)},
		{"notionToken/too short", "secret_" + g(42, 42, secpatAlnum)},
		{"notionToken/too long", "secret_" + g(43, 60, secpatAlnum)},
		{"atlassianToken/too short", "ATATT3" + g(44, 10, secpatURLSafe)},
		{"databricksToken/too short", "dapi" + g(45, 31, secpatHex)},
		{"databricksToken/longer hash", "dapi" + g(46, 64, secpatHex)},
		{"newRelicKey/too short", "NRAK-" + g(47, 26, secpatUpper)},
		{"dropboxToken/too short", "sl." + g(48, 100, secpatURLSafe)},
		{"dropboxToken/inside another word", "ssl." + g(49, 140, secpatURLSafe)},

		{"telegramBotToken/short id", "1234567:AA" + g(50, 33, secpatURLSafe)},
		{"telegramBotToken/too short", "1234567890:AA" + g(51, 32, secpatURLSafe)},
		{"discordWebhook/short token", "https://discord.com/api/webhooks/123456789012345678/" + g(52, 30, secpatURLSafe)},
		{"sentryDsn/short key", "https://" + g(53, 31, secpatHex) + "@o4504321.ingest.sentry.io/4504322"},
		{"sentryDsn/self hosted project page", "https://sentry.io/organizations/acme/issues/"},

		{"jwt/two segments", jwtHeader + "." + jwtPayload},
		{"jwt/only a header", jwtHeader + "." + g(54, 20, secpatURLSafe)},
		{"basicAuthUrl/no password", "https://user@example.com/"},
		{"basicAuthUrl/at sign in the path", "https://example.com/@user/package"},
		{"basicAuthUrl/port number", "https://example.com:8080/path"},
		{"basicAuthUrl/profile handle", "https://medium.com/@someone/some-article"},
		{"dbConnectionString/no credentials", "postgres://localhost:5432/mydb"},
		{"dbConnectionString/no password", "mongodb://db.example.com:27017/admin?replicaSet=rs0"},
		{"dbConnectionString/no credentials redis", "redis://localhost:6379"},

		// The existing matchers own these, so this engine must stay out of the way
		{"existing/github ghp_", "ghp_" + g(55, 36, secpatAlnum)},
		{"existing/aws access key", "AKIAIOSFODNN7EXAMPLE"},
		{"existing/gcp api key", "AIzaSy" + g(56, 33, secpatURLSafe)},

		// Lots of strings that are long enough to get past the length check,
		// and some even contain a prefix, but none of them are secrets
		{"plain/sentence", "The quick brown fox jumps over the lazy dog, sk_live_ and all"},
		{"plain/url", "https://example.com/some/path/to/a/resource?with=query&and=params"},
		{"plain/css selector", "div.container > ul.menu li.item:not(.disabled) a[href^=http]"},
		{"plain/hex digest", g(57, 64, secpatHex)},
		{"plain/uuid", "123e4567-e89b-12d3-a456-426614174000"},
		{"plain/path", "./node_modules/@babel/runtime/helpers/esm/defineProperty.js"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secrets := secpatScan(`var k = "` + c.value + `";`)

			if len(secrets) != 0 {
				t.Errorf("want no secrets for %q; have %+v", c.value, secrets[0])
			}
		})
	}
}

func TestPatternSecretMatcherObjectContext(t *testing.T) {
	key := "sk_live_" + secpatGen(1, 32, secpatAlnum)

	secrets := secpatScan(`var config = {name: "billing", stripeKey: "` + key + `", mode: "prod", retries: 3};`)

	if len(secrets) != 1 {
		t.Fatalf("want exactly 1 secret; have %d", len(secrets))
	}

	if secrets[0].Kind != "stripeSecretKey" {
		t.Errorf("want kind stripeSecretKey; have %s", secrets[0].Kind)
	}

	ctx, ok := secrets[0].Context.(map[string]string)
	if !ok {
		t.Fatalf("want context of type map[string]string; have %T", secrets[0].Context)
	}

	want := map[string]string{
		"name":      "billing",
		"stripeKey": key,
		"mode":      "prod",
		"retries":   "",
	}

	if len(ctx) != len(want) {
		t.Errorf("want %d keys in context; have %d: %v", len(want), len(ctx), ctx)
	}
	for k, v := range want {
		if ctx[k] != v {
			t.Errorf("want context[%q] = %q; have %q", k, v, ctx[k])
		}
	}
}

func TestPatternSecretMatcherNoContextOutsideObjects(t *testing.T) {
	key := "sk_live_" + secpatGen(2, 32, secpatAlnum)

	cases := map[string]string{
		"variable":      `var k = "` + key + `";`,
		"array":         `var k = ["a", "` + key + `"];`,
		"call argument": `init("` + key + `");`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			secrets := secpatScan(src)

			if len(secrets) != 1 {
				t.Fatalf("want exactly 1 secret; have %d", len(secrets))
			}
			if secrets[0].Context != nil {
				t.Errorf("want nil context; have %v", secrets[0].Context)
			}
		})
	}
}

func TestPatternSecretMatcherMultipleSecrets(t *testing.T) {
	g := secpatGen

	src := fmt.Sprintf(`
		var a = "npm_%s";
		function f() {
			return {
				slack: "xoxb-123456789012-1234567890123-%s",
				other: "not a secret at all, just a longish string",
			}
		}
		var b = "ghs_%s";
	`, g(1, 36, secpatAlnum), g(2, 24, secpatAlnum), g(3, 36, secpatAlnum))

	secrets := secpatScan(src)

	want := []string{"npmToken", "slackToken", "githubToken"}
	if len(secrets) != len(want) {
		t.Fatalf("want %d secrets; have %d: %+v", len(want), len(secrets), secrets)
	}

	for i, kind := range want {
		if secrets[i].Kind != kind {
			t.Errorf("want secret %d to be %s; have %s", i, kind, secrets[i].Kind)
		}
	}
}

// Raw strings still have their escape sequences in them and a trailing
// backslash can be left over after the quotes are removed, so make sure that
// odd input does not upset the escape handling.
func TestPatternSecretMatcherOddEscapes(t *testing.T) {
	cases := map[string]string{
		"trailing backslash": `var k = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\";`,
		"bad hex escape":     `var k = "aaaaaaaaaaaaaaaa\xZZaaaaaaaaaaaaaaaa\u12aaaaaaaaaaaaaaaaaaaaaaaaaaaa";`,
		"escaped quote":      `var k = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";`,
		"windows path":       `var k = "C:\\Users\\someone\\AppData\\Local\\Temp\\some-file-name.txt";`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if secrets := secpatScan(src); len(secrets) != 0 {
				t.Errorf("want no secrets; have %+v", secrets[0])
			}
		})
	}
}

func TestSecpatRulesWellFormed(t *testing.T) {
	seen := make(map[string]bool)

	for _, r := range secpatRules {
		if r.name == "" {
			t.Errorf("rule with regex %v has no name", r.re)
			continue
		}

		if seen[r.name] {
			t.Errorf("rule name %q is used more than once", r.name)
		}
		seen[r.name] = true

		if r.re == nil {
			t.Errorf("rule %q has no regular expression", r.name)
		}

		switch r.severity {
		case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh:
		default:
			t.Errorf("rule %q has unknown severity %q", r.name, r.severity)
		}

		for _, p := range r.prefixes {
			// An empty prefix is contained in every string, which would
			// silently turn the speed gate off for the rule
			if p == "" {
				t.Errorf("rule %q has an empty prefix", r.name)
			}
		}
	}
}

func TestSecpatMinLength(t *testing.T) {
	cases := []struct {
		expr     string
		expected int
	}{
		{`abc`, 3},
		{`ab{3,}c?`, 4},
		{`(?:ab|c)d`, 2},
		{`^x$`, 1},
		{`[a-f]{5}`, 5},
		{`a*`, 0},
		{`(a|bc)+`, 1},
		{`x{0,300}`, 0},
		{`(?:^|[^a-z])(?:sk|rk)_live_[0-9A-Za-z]{24,}`, 32},
		{`\bfoo\b`, 3},
	}

	for _, c := range cases {
		actual := secpatMinLength(regexp.MustCompile(c.expr))

		if actual != c.expected {
			t.Errorf("want %d for secpatMinLength(%q); have %d", c.expected, c.expr, actual)
		}
	}
}

// The length check must never discard a string that a rule would have matched
func TestSecpatMinLenIsSafe(t *testing.T) {
	if secpatMinLen <= 0 {
		t.Fatalf("want secpatMinLen > 0 so the length check does something; have %d", secpatMinLen)
	}

	for _, c := range secpatPositiveCases() {
		if len(c.value) < secpatMinLen {
			t.Errorf("sample %q for %s is shorter than secpatMinLen (%d)", c.value, c.name, secpatMinLen)
		}
	}
}

func BenchmarkPatternSecretMatcher(b *testing.B) {
	var src strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(
			&src,
			`var a%d = {id: "item-%d", label: "Some label text number %d", url: "https://example.com/path/%d?x=1", cls: "btn btn-primary btn-lg"};`+"\n",
			i, i, i, i,
		)
	}

	a := NewAnalyzer([]byte(src.String()))
	m := patternSecretMatcher()

	nodes := make([]*Node, 0)
	a.Query(m.Query, func(n *Node) {
		nodes = append(nodes, n)
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, n := range nodes {
			m.Fn(n)
		}
	}
}
