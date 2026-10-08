package control

import (
	"fmt"
	"net/http"
	"strings"
)

// The console is Chinese-first and can be switched to English; both choices
// are cookies set through GET /console/prefs (spec section 51). Templates
// carry English message ids and call {{T "..."}}; a missing translation falls
// back to the English text, so the console is never half-blank.
const (
	consoleLangCookie   = "xunara_lang"
	consoleAccentCookie = "xunara_accent"

	consoleDefaultLang   = "en"
	consoleDefaultAccent = "blue"
)

// consoleLangs are the selectable languages; consoleAccents the selectable
// accent palettes (the token blocks live in the console stylesheet).
var (
	consoleLangs   = map[string]bool{"zh": true, "en": true}
	consoleAccents = map[string]bool{"blue": true, "teal": true}
)

// consoleDict is one language: text maps a trimmed text node or attribute
// value to its translation, block maps the trimmed inner markup of a <p> to a
// translated paragraph (used for prose that contains inline <code>/<em>).
type consoleDict struct {
	text  map[string]string
	block map[string]string
}

// consoleTranslations holds one dictionary per language keyed by message id.
var consoleTranslations = map[string]consoleDict{"zh": {text: consoleZH, block: consoleZHBlock}}

// consoleLangFromRequest resolves the UI language: the preference cookie the
// operator set in the console wins, otherwise the browser's Accept-Language
// decides between the two supported languages, and an absent or unhelpful
// header keeps the console in English.
func consoleLangFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(consoleLangCookie); err == nil && consoleLangs[cookie.Value] {
		return cookie.Value
	}
	return acceptLanguage(consoleLangs, r.Header.Get("Accept-Language"))
}

// acceptLanguage returns the language a browser asks for, restricted to the
// supported set: "zh" wins when it is preferred over "en", and the fallback
// is English. Matching is on the primary subtag ("zh-CN" matches "zh"), the
// way browsers and RFC 9110 define it.
func acceptLanguage(supported map[string]bool, header string) string {
	best, bestQuality := "", -1.0
	for _, part := range strings.Split(header, ",") {
		tag, quality := strings.TrimSpace(part), 1.0
		if semi := strings.IndexByte(tag, ';'); semi >= 0 {
			params := tag[semi+1:]
			tag = strings.TrimSpace(tag[:semi])
			if q := strings.Index(params, "q="); q >= 0 {
				quality = parseQuality(params[q+2:])
			}
		}
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || tag == "*" {
			continue
		}
		primary := tag
		if dash := strings.IndexByte(primary, '-'); dash >= 0 {
			primary = primary[:dash]
		}
		if !supported[primary] {
			continue
		}
		if quality > bestQuality {
			best, bestQuality = primary, quality
		}
	}
	if best == "" {
		return consoleDefaultLang
	}
	return best
}

// parseQuality reads the q value of one Accept-Language entry.
func parseQuality(value string) float64 {
	value = strings.TrimSpace(value)
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = strings.TrimSpace(value[:semi])
	}
	var quality float64
	if _, err := fmt.Sscanf(value, "%g", &quality); err != nil {
		return 1.0
	}
	if quality < 0 {
		return 0
	}
	if quality > 1 {
		return 1
	}
	return quality
}

// consoleAccentFromRequest resolves the accent palette from the cookie.
func consoleAccentFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(consoleAccentCookie); err == nil && consoleAccents[cookie.Value] {
		return cookie.Value
	}
	return consoleDefaultAccent
}

// translator returns the T template function for one language: it looks the
// message id up in the dictionary and formats it when arguments are given.
// Unknown ids render as the English source text.
func translator(lang string) func(string, ...any) string {
	dict := consoleTranslations[lang].text
	return func(key string, args ...any) string {
		text := key
		if translated, ok := dict[key]; ok {
			text = translated
		}
		if len(args) == 0 {
			return text
		}
		return fmt.Sprintf(text, args...)
	}
}

// handleConsolePrefs stores the language and accent preferences and returns
// the operator to where they came from. Both parameters are optional, so one
// link can change only one of them. The language menu is plain links, so it
// works without JavaScript.
func (s *Server) handleConsolePrefs(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/console/"
	}
	if lang := r.URL.Query().Get("lang"); lang != "" {
		if !consoleLangs[lang] {
			lang = consoleDefaultLang
		}
		s.setPrefCookie(w, consoleLangCookie, lang)
	}
	if accent := r.URL.Query().Get("accent"); accent != "" {
		if !consoleAccents[accent] {
			accent = consoleDefaultAccent
		}
		s.setPrefCookie(w, consoleAccentCookie, accent)
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// setPrefCookie stores one long-lived preference. The values are not secrets,
// but they are still scoped and SameSite=Lax like the session cookie.
func (s *Server) setPrefCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
	})
}

// consoleNavItem is one console section in the sidebar.
type consoleNavItem struct {
	Key  string
	Href string
}

// consoleNavGroup is a labelled group of console sections. An empty label
// renders the group without a heading (the top-level items).
type consoleNavGroup struct {
	Label string
	Items []consoleNavItem
}

// consoleNav is the sidebar structure: the same sections as before, grouped
// the way operators look for them (network, identity, credentials, ...).
var consoleNav = []consoleNavGroup{
	{Items: []consoleNavItem{
		{Key: "overview", Href: "/console/"},
	}},
	{Label: "Network", Items: []consoleNavItem{
		{Key: "machines", Href: "/console/machines"},
		{Key: "exit-nodes", Href: "/console/exit-nodes"},
		{Key: "services", Href: "/console/services"},
		{Key: "relays", Href: "/console/relays"},
		{Key: "serve", Href: "/console/serve"},
		{Key: "devices", Href: "/console/devices"},
	}},
	{Label: "Identity", Items: []consoleNavItem{
		{Key: "users", Href: "/console/users"},
		{Key: "passkeys", Href: "/console/passkeys"},
		{Key: "dns", Href: "/console/dns"},
		{Key: "derp", Href: "/console/derp"},
	}},
	{Label: "Credentials", Items: []consoleNavItem{
		{Key: "auth-keys", Href: "/console/auth-keys"},
		{Key: "agents", Href: "/console/agents"},
		{Key: "api-keys", Href: "/console/api-keys"},
	}},
	{Label: "Collaboration", Items: []consoleNavItem{
		{Key: "shares", Href: "/console/shares"},
		{Key: "reach", Href: "/console/reach"},
		{Key: "flux", Href: "/console/flux"},
		{Key: "ssh-check", Href: "/console/ssh-check"},
		{Key: "webhooks", Href: "/console/webhooks"},
	}},
	{Label: "Governance", Items: []consoleNavItem{
		{Key: "policy", Href: "/console/policy"},
		{Key: "security", Href: "/console/security"},
		{Key: "audit", Href: "/console/audit"},
	}},
}

// consoleLedes is the one-line description under each page title. The values
// are English message ids translated at render time.
var consoleLedes = map[string]string{
	"overview":   "Your tailnet at a glance.",
	"machines":   "Devices registered to this tailnet.",
	"exit-nodes": "Which devices route the default route, and who selected them.",
	"services":   "Services nodes publish about themselves (Xunara Atlas).",
	"relays":     "Peer relays nodes offer and the grants that allow their use.",
	"serve":      "Ports shared through Xunara Serve.",
	"devices":    "Devices waiting for approval, with their machine keys.",
	"users":      "People and roles in this tailnet.",
	"passkeys":   "Passkeys that sign you in without a password.",
	"dns":        "MagicDNS records and resolvers this deployment serves.",
	"derp":       "Which DERP regions this organization serves.",
	"auth-keys":  "Pre-authentication keys for unattended devices.",
	"agents":     "Agent tokens that authenticate self-hosted agents.",
	"api-keys":   "API keys for the HTTP v2 management API.",
	"shares":     "Machines shared across organizations.",
	"reach":      "Remote command sessions and their approvals.",
	"flux":       "End-to-end encrypted file transfers.",
	"ssh-check":  "Tailscale SSH check approvals.",
	"webhooks":   "Event receivers and their delivery attempts.",
	"policy":     "The ACL policy document in force (read-only).",
	"security":   "Security posture and findings.",
	"audit":      "Who did what, newest first.",
}

// consoleNavGroups resolves the sidebar for one active section: the group
// labels and titles stay message ids, translated when the page renders.
func consoleNavGroups(active string) []map[string]any {
	groups := make([]map[string]any, 0, len(consoleNav))
	for _, group := range consoleNav {
		items := make([]map[string]any, 0, len(group.Items))
		for _, item := range group.Items {
			items = append(items, map[string]any{
				"Title":  consoleTitles[item.Key],
				"Href":   item.Href,
				"Active": item.Key == active,
			})
		}
		groups = append(groups, map[string]any{"Label": group.Label, "Items": items})
	}
	return groups
}
