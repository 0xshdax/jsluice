package jsluice

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// This file implements a table-driven secret detector. Every rule describes a
// well-known token format that has a distinctive prefix, or is otherwise
// structurally anchored (fixed alphabet and length, or a recognisable URL
// shape). There is deliberately no generic entropy or bare-hex matching, so
// that the false positive rate stays low.
//
// All of the rules are run by a single SecretMatcher so each string literal is
// only visited once. JavaScript files contain a very large number of string
// literals, so a typical string is rejected as cheaply as possible:
//
//   - strings shorter than the shortest possible match are skipped outright
//   - a rule's regular expression only runs if the string contains one of the
//     literal prefixes listed for that rule
//   - all regular expressions are compiled once, at package initialisation

// secpatRule describes a single secret format.
type secpatRule struct {
	// name is the Kind of any Secret found by the rule, e.g. "stripeSecretKey"
	name string

	// severity is the Severity of any Secret found by the rule
	severity Severity

	// prefixes is a fast-path gate. If it is not empty the regular expression
	// is only run for strings that contain at least one of the prefixes.
	prefixes []string

	// re is the actual match
	re *regexp.Regexp
}

const (
	// secpatLeft is a left boundary for a token that starts with a letter or
	// digit. The token has to be at the start of the string, or follow
	// something that cannot be part of a longer identifier-like run. That
	// stops e.g. 'cache-key-<hex>' being mistaken for a Mailgun 'key-<hex>'
	// key, or 'client_secret_<base62>' for a Notion 'secret_<base62>' one.
	secpatLeft = `(?:^|[^0-9A-Za-z_\-])`

	// secpatRight is a right boundary for tokens of a fixed length. It stops
	// the first N characters of a longer hash or base64 blob being mistaken
	// for a token. A '-' is allowed to follow so that suffixes like
	// Databricks' '-2' do not get in the way.
	secpatRight = `(?:$|[^0-9A-Za-z_])`
)

// secpatToken compiles expr, requiring the match to be preceded
// by secpatLeft.
func secpatToken(expr string) *regexp.Regexp {
	return regexp.MustCompile(secpatLeft + `(?:` + expr + `)`)
}

// secpatTokenExact compiles expr, requiring the match to be both
// preceded by secpatLeft and followed by secpatRight. It is meant
// for fixed-length tokens with a short or generic prefix.
func secpatTokenExact(expr string) *regexp.Regexp {
	return regexp.MustCompile(secpatLeft + `(?:` + expr + `)` + secpatRight)
}

// secpatRules is the list of rules run by patternSecretMatcher(). The columns
// are: name (Secret.Kind), severity, prefix gate, regular expression.
//
// The order matters because the first rule to match a string wins: specific
// vendor formats come first, and the generic URL and JWT shapes come last.
var secpatRules = []secpatRule{
	// A PEM / OpenSSH / PGP private key. The header on its own is not enough
	// because cryptography libraries are full of strings like it; the key
	// body has to be there as well. Any \n escapes have been decoded by the
	// time the regular expression runs, so the body is on later lines.
	{"privateKey", SeverityHigh, []string{"-----BEGIN"},
		regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*[A-Za-z0-9+/=]{32,}`)},

	// GitHub. ghp_ tokens are deliberately absent: githubKeyMatcher owns those.
	{"githubToken", SeverityHigh, []string{"gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		secpatToken(`gh[ousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{80,}`)},
	{"gitlabToken", SeverityHigh, []string{"glpat-"},
		secpatToken(`glpat-[0-9A-Za-z_\-]{20}`)},

	// Slack. Real tokens always have a numeric segment straight after the
	// prefix, which rules out placeholders like 'xoxb-your-token-here'.
	{"slackToken", SeverityHigh, []string{"xox"},
		secpatToken(`xox[abeprs]-[0-9][0-9A-Za-z-]{9,}`)},
	{"slackWebhook", SeverityHigh, []string{"hooks.slack.com"},
		regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z]{20,}`)},

	// Stripe
	{"stripeSecretKey", SeverityHigh, []string{"sk_live_", "rk_live_"},
		secpatToken(`(?:sk|rk)_live_[0-9A-Za-z]{24,}`)},
	{"stripeTestKey", SeverityLow, []string{"sk_test_", "rk_test_"},
		secpatToken(`(?:sk|rk)_test_[0-9A-Za-z]{24,}`)},
	{"stripePublishableKey", SeverityInfo, []string{"pk_live_"},
		secpatToken(`pk_live_[0-9A-Za-z]{24,}`)},

	// Google OAuth
	{"googleOAuthClientSecret", SeverityHigh, []string{"GOCSPX-"},
		secpatToken(`GOCSPX-[0-9A-Za-z_\-]{28}`)},
	{"googleOAuthToken", SeverityMedium, []string{"ya29."},
		secpatToken(`ya29\.[0-9A-Za-z_\-]{30,}`)},

	// Email / messaging providers. SendGrid keys are distinctive on their own,
	// but the Twilio SIDs, Mailgun and Mailchimp keys are hex strings with a
	// short prefix (or, for Mailchimp, a suffix), so they need to be exactly
	// the right length rather than just start the right way.
	{"sendgridKey", SeverityHigh, []string{"SG."},
		secpatToken(`SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`)},
	{"twilioApiKey", SeverityMedium, []string{"SK"},
		secpatTokenExact(`SK[0-9a-f]{32}`)},
	{"twilioAccountSid", SeverityLow, []string{"AC"},
		secpatTokenExact(`AC[0-9a-f]{32}`)},
	{"mailgunKey", SeverityMedium, []string{"key-"},
		secpatTokenExact(`key-[0-9a-f]{32}`)},
	{"mailchimpKey", SeverityMedium, []string{"-us"},
		secpatTokenExact(`[0-9a-f]{32}-us[0-9]{1,2}`)},

	// Package registries and e-commerce
	{"npmToken", SeverityHigh, []string{"npm_"},
		secpatTokenExact(`npm_[0-9A-Za-z]{36}`)},
	{"shopifyToken", SeverityHigh, []string{"shpat_", "shpca_", "shppa_", "shpss_"},
		secpatToken(`shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}`)},
	{"squareAccessToken", SeverityHigh, []string{"sq0atp-"},
		secpatToken(`sq0atp-[0-9A-Za-z_\-]{22}`)},
	{"squareOAuthSecret", SeverityHigh, []string{"sq0csp-"},
		secpatToken(`sq0csp-[0-9A-Za-z_\-]{43}`)},
	// EAAA is also how some base64 blobs and Facebook tokens begin, so this
	// one has to be exactly 64 characters long.
	{"squareToken", SeverityHigh, []string{"EAAA"},
		secpatTokenExact(`EAAA[0-9A-Za-z_\-]{60}`)},

	// Cloud / infrastructure
	{"digitaloceanToken", SeverityHigh, []string{"dop_v1_", "doo_v1_", "dor_v1_"},
		secpatToken(`do[por]_v1_[0-9a-f]{64}`)},
	{"mapboxSecretToken", SeverityHigh, []string{"sk.eyJ"},
		secpatToken(`sk\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}`)},
	{"mapboxPublicToken", SeverityInfo, []string{"pk.eyJ"},
		secpatToken(`pk\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}`)},

	// AI providers
	{"openaiKey", SeverityHigh, []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "T3BlbkFJ"},
		secpatToken(`sk-(?:proj|svcacct|admin)-[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`)},
	{"anthropicKey", SeverityHigh, []string{"sk-ant-"},
		secpatToken(`sk-ant-[0-9A-Za-z_\-]{20,}`)},
	{"huggingfaceToken", SeverityHigh, []string{"hf_"},
		secpatToken(`hf_[0-9A-Za-z]{34}`)},

	// SaaS / developer tools
	{"postmanKey", SeverityHigh, []string{"PMAK-"},
		secpatToken(`PMAK-[0-9a-f]{24}-[0-9a-f]{34}`)},
	{"figmaToken", SeverityHigh, []string{"figd_"},
		secpatToken(`figd_[0-9A-Za-z_\-]{40,}`)},
	{"linearKey", SeverityHigh, []string{"lin_api_"},
		secpatToken(`lin_api_[0-9A-Za-z]{40}`)},
	// 'secret_' is a very common way to start a string, so the legacy Notion
	// format has to be exactly the right length as well.
	{"notionToken", SeverityHigh, []string{"secret_", "ntn_"},
		secpatToken(`secret_[0-9A-Za-z]{43}` + secpatRight + `|ntn_[0-9A-Za-z]{40,}`)},
	{"atlassianToken", SeverityHigh, []string{"ATATT3"},
		secpatToken(`ATATT3[0-9A-Za-z_\-=.]{20,}`)},
	{"databricksToken", SeverityHigh, []string{"dapi"},
		secpatTokenExact(`dapi[0-9a-f]{32}(?:-[0-9]+)?`)},
	{"newRelicKey", SeverityHigh, []string{"NRAK-"},
		secpatToken(`NRAK-[0-9A-Z]{27}`)},
	{"dropboxToken", SeverityMedium, []string{"sl."},
		secpatToken(`sl\.[0-9A-Za-z_\-]{130,}`)},

	// Telegram bot tokens are usually embedded in an API URL, right after
	// 'bot', so the left boundary only has to stop the numeric ID being
	// the tail of a longer number.
	{"telegramBotToken", SeverityHigh, []string{":AA"},
		regexp.MustCompile(`(?:^|[^0-9])[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}` + secpatRight)},

	// Webhook / DSN URLs
	{"discordWebhook", SeverityHigh, []string{"/webhooks/"},
		regexp.MustCompile(`https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v[0-9]+)?/webhooks/[0-9]{17,20}/[0-9A-Za-z_\-]{60,}`)},
	{"sentryDsn", SeverityMedium, []string{"sentry.io"},
		regexp.MustCompile(`https://[0-9a-f]{32}@(?:[0-9a-z.\-]+\.ingest\.(?:[a-z]{2}\.)?)?sentry\.io/[0-9]+`)},

	// Generic shapes. These go last so that a more specific rule gets to
	// claim e.g. a GitHub token used as the password in a URL.
	{"dbConnectionString", SeverityHigh, []string{"://"},
		regexp.MustCompile(`(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[A-Za-z0-9._%\-]*:[^@/\s:]{3,}@`)},
	{"jwt", SeverityLow, []string{"eyJ"},
		secpatToken(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"basicAuthUrl", SeverityMedium, []string{"://"},
		regexp.MustCompile(`https?://[A-Za-z0-9._%\-]+:[^@/\s:]{3,}@[A-Za-z0-9.\-]+`)},
}

// secpatMinLen is the length of the shortest string that any of the rules
// could possibly match. Most string literals in a JavaScript file are shorter
// than that, so checking it first saves a lot of work.
var secpatMinLen = secpatShortestMatch(secpatRules)

// secpatShortestMatch returns the length of the shortest string that
// any of the supplied rules could match.
func secpatShortestMatch(rules []secpatRule) int {
	shortest := 0
	for i, rule := range rules {
		if l := secpatMinLength(rule.re); i == 0 || l < shortest {
			shortest = l
		}
	}
	return shortest
}

// secpatMinLength returns the length of the shortest string that
// the regular expression could match.
func secpatMinLength(re *regexp.Regexp) int {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		// Can't happen: the expression has already been compiled. Returning
		// zero is always safe though; it just disables the optimisation
		return 0
	}
	return secpatNodeMinLength(parsed)
}

// secpatNodeMinLength returns the length of the shortest string that the
// parsed regular expression could match. It never overestimates.
func secpatNodeMinLength(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)

	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1

	case syntax.OpCapture, syntax.OpPlus:
		return secpatNodeMinLength(re.Sub[0])

	case syntax.OpRepeat:
		return re.Min * secpatNodeMinLength(re.Sub[0])

	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total += secpatNodeMinLength(sub)
		}
		return total

	case syntax.OpAlternate:
		shortest := 0
		for i, sub := range re.Sub {
			if l := secpatNodeMinLength(sub); i == 0 || l < shortest {
				shortest = l
			}
		}
		return shortest

	default:
		// OpStar and OpQuest can match nothing, as can the empty-width
		// assertions like ^, $ and \b
		return 0
	}
}

// secpatFirstMatch returns the first rule that matches the string, or
// nil if none do.
func secpatFirstMatch(str string) *secpatRule {
	for i := range secpatRules {
		rule := &secpatRules[i]

		if len(rule.prefixes) > 0 && !secpatContainsAny(str, rule.prefixes) {
			continue
		}

		if rule.re.MatchString(str) {
			return rule
		}
	}
	return nil
}

// secpatContainsAny returns true if str contains at least one of subs
func secpatContainsAny(str string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(str, sub) {
			return true
		}
	}
	return false
}

// patternSecretMatcher returns a single SecretMatcher that runs every rule
// in secpatRules against each string literal in one pass.
func patternSecretMatcher() SecretMatcher {
	return SecretMatcher{"(string) @matches", func(n *Node) *Secret {
		str := n.RawString()

		// Remember that there are a *lot* of strings in JS files, and
		// most of them are far too short to be any of these secrets.
		if len(str) < secpatMinLen {
			return nil
		}

		// A raw string still has its escape sequences in it. They are common
		// enough in the places secrets live (e.g. 'https:\/\/hooks.slack.com'
		// from a JSON encoder, or '\n' between lines of a .env file) to make
		// a difference to the match, so we decode them when there are any.
		if strings.IndexByte(str, '\\') >= 0 {
			str = DecodeString(str)
		}

		rule := secpatFirstMatch(str)
		if rule == nil {
			return nil
		}

		match := &Secret{
			Kind:     rule.name,
			Severity: rule.severity,
			Data: map[string]string{
				"match":   str,
				"pattern": rule.name,
			},
		}

		// If the secret is in an object we want to include that whole object as context
		parent := n.Parent()
		if parent == nil || parent.Type() != "pair" {
			return match
		}

		grandparent := parent.Parent()
		if grandparent == nil || grandparent.Type() != "object" {
			return match
		}

		match.Context = grandparent.AsObject().AsMap()

		return match
	}}
}
