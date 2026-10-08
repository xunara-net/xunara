package control

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// getRequestWithLanguage performs a GET carrying an Accept-Language header, so
// a test can act like a browser that has not chosen a console language yet.
func getRequestWithLanguage(t *testing.T, client *http.Client, rawURL string, language string, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	if language != "" {
		req.Header.Set("Accept-Language", language)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestConsoleLanguageFromBrowser pins the language resolution order: the
// operator's cookie wins, then the browser's Accept-Language, then English.
func TestConsoleLanguageFromBrowser(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	for _, tc := range []struct {
		name     string
		language string
		want     []string
		absent   []string
	}{
		{
			name:     "chinese browser",
			language: "zh-CN,zh;q=0.9,en;q=0.8",
			want:     []string{`<html lang="zh"`, "概览", "网络", "设备", "退出", "跳到主要内容"},
			absent:   []string{`<html lang="en"`},
		},
		{
			name:     "english browser",
			language: "en-US,en;q=0.9",
			want:     []string{`<html lang="en"`, "Overview", "Machines", "Sign out"},
		},
		{
			name:   "no preference",
			absent: []string{`<html lang="zh"`},
			want:   []string{`<html lang="en"`, "Overview"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bodyString(t, getRequestWithLanguage(t, client, hs.URL+"/console/machines", tc.language, cookie))
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("console does not contain %q", want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(body, absent) {
					t.Errorf("console unexpectedly contains %q", absent)
				}
			}
		})
	}

	// A saved preference beats the browser's header.
	pref := &http.Cookie{Name: consoleLangCookie, Value: "zh"}
	body := bodyString(t, getRequestWithLanguage(t, client, hs.URL+"/console/machines", "en-US,en;q=0.9", cookie, pref))
	if !strings.Contains(body, `<html lang="zh"`) || !strings.Contains(body, "设备") {
		t.Errorf("saved language preference was ignored:\n%.600s", body)
	}
}

// TestConsoleChinesePages checks that page bodies, not only the shell, render
// in Chinese: headings, table headers, buttons and empty states.
func TestConsoleChinesePages(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	session := loginLocal(t, client, hs.URL, "/console/")
	pref := &http.Cookie{Name: consoleLangCookie, Value: "zh"}

	for _, tc := range []struct {
		path   string
		want   []string
		absent []string
	}{
		{
			path:   "/console/",
			want:   []string{"概览", "在线设备", "设备总数", "访问控制", "网络锁", "工作负载身份"},
			absent: []string{"machines online", "Access control", "Tailnet lock"},
		},
		{
			path:   "/console/devices",
			want:   []string{"设备授权", "暂无等待审批的设备。"},
			absent: []string{"No devices are waiting for approval."},
		},
		{
			path:   "/console/auth-keys",
			want:   []string{"预认证密钥", "创建密钥", "暂无预认证密钥。", "可复用", "有效期"},
			absent: []string{"No auth keys.", "Reusable"},
		},
		{
			path:   "/console/dns",
			want:   []string{"DNS 记录", "暂无额外 DNS 记录。"},
			absent: []string{"No extra DNS records."},
		},
		{
			path:   "/console/policy",
			want:   []string{"策略文档", "每台设备都可以访问其它设备"},
			absent: []string{"No policy document is configured"},
		},
		{
			path:   "/console/ssh-check",
			want:   []string{"SSH 审批", "没有匹配的 SSH 审批。"},
			absent: []string{"No SSH checks match."},
		},
	} {
		body := bodyString(t, getRequestWithLanguage(t, client, hs.URL+tc.path, "zh-CN,zh;q=0.9", session, pref))
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s does not contain %q:\n%.800s", tc.path, want, body)
			}
		}
		for _, absent := range tc.absent {
			if strings.Contains(body, absent) {
				t.Errorf("GET %s still shows %q in Chinese:\n%.800s", tc.path, absent, body)
			}
		}
	}
}

// TestConsolePrefs covers the preference endpoint: it stores the language and
// accent in long-lived cookies, refuses to redirect off-site, and ignores
// values it does not know.
func TestConsolePrefs(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	resp := getRequest(t, client, hs.URL+"/console/prefs?lang=zh&accent=teal&return_to=/console/dns", cookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /console/prefs status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/console/dns" {
		t.Errorf("prefs redirect = %q, want /console/dns", loc)
	}
	if c := cookieNamed(t, resp, consoleLangCookie); c.Value != "zh" || c.MaxAge <= 0 || c.Path != "/" {
		t.Errorf("language cookie = %+v, want zh with a long life on /", c)
	}
	if c := cookieNamed(t, resp, consoleAccentCookie); c.Value != "teal" {
		t.Errorf("accent cookie = %q, want teal", c.Value)
	}

	// The saved pair is what the pages then render with.
	body := bodyString(t, getRequestWithLanguage(t, client, hs.URL+"/console/dns", "",
		cookie, cookieNamed(t, resp, consoleLangCookie), cookieNamed(t, resp, consoleAccentCookie)))
	if !strings.Contains(body, `data-accent="teal"`) || !strings.Contains(body, `<html lang="zh"`) {
		t.Errorf("console ignored the saved preferences:\n%.400s", body)
	}
	if !strings.Contains(body, `class="active" aria-current="page"`) {
		t.Error("console does not mark the active section")
	}

	// Off-site and protocol-relative return paths are refused, and unknown
	// values fall back to the defaults instead of being stored.
	for _, tc := range []struct{ query, want string }{
		{"lang=zh&return_to=https://evil.example/", "/console/"},
		{"lang=zh&return_to=//evil.example/", "/console/"},
		{"lang=zh&return_to=/console/machines", "/console/machines"},
	} {
		resp := getRequest(t, client, hs.URL+"/console/prefs?"+tc.query, cookie)
		if loc := resp.Header.Get("Location"); loc != tc.want {
			t.Errorf("prefs %q redirect = %q, want %q", tc.query, loc, tc.want)
		}
	}
	resp = getRequest(t, client, hs.URL+"/console/prefs?lang=de&accent=rainbow", cookie)
	if c := cookieNamed(t, resp, consoleLangCookie); c.Value != consoleDefaultLang {
		t.Errorf("unknown language stored %q, want %q", c.Value, consoleDefaultLang)
	}
	if c := cookieNamed(t, resp, consoleAccentCookie); c.Value != consoleDefaultAccent {
		t.Errorf("unknown accent stored %q, want %q", c.Value, consoleDefaultAccent)
	}
}

// TestLocalizeHTML covers the render-time translation rules: text nodes and
// visible attributes translate, code samples, scripts and secrets do not, and
// English output is untouched.
func TestLocalizeHTML(t *testing.T) {
	dict := consoleDict{
		text: map[string]string{
			"Cancel":         "取消",
			"Sign out":       "退出",
			"Tailnet & lock": "网络锁",
		},
		block: map[string]string{
			"Say <code>hi</code> now.": "现在说 <code>hi</code>。",
		},
	}
	page := strings.Join([]string{
		`<p>Say <code>hi</code> now.</p>`,
		`<p>Untranslated prose stays as it is.</p>`,
		`<td>Cancel</td>`,
		`<pre>Cancel</pre>`,
		`<code>Cancel</code>`,
		`<script>var label = "Cancel";</script>`,
		`<style>.a { content: "Cancel" }</style>`,
		`<button placeholder="Cancel" aria-label="Sign out" title="Cancel">Sign out</button>`,
		`<span>Tailnet &amp; lock</span>`,
	}, "")

	got := localizeHTML(dict, page)
	for _, want := range []string{
		"现在说 <code>hi</code>。",
		"<td>取消</td>",
		"<pre>Cancel</pre>",
		"<code>Cancel</code>",
		`<script>var label = "Cancel";</script>`,
		`placeholder="取消"`,
		`aria-label="退出"`,
		`title="取消"`,
		">退出</button>",
		"网络锁",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("localized page does not contain %q:\n%s", want, got)
		}
	}
	for _, absent := range []string{`<td>Cancel</td>`, `>Sign out</button>`} {
		if strings.Contains(got, absent) {
			t.Errorf("localized page still contains %q:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "Untranslated prose stays as it is.") {
		t.Error("an untranslated paragraph was dropped or altered")
	}

	// Prefix rules translate a sentence built around a runtime value, and
	// T formats the counts the templates pass in.
	pref := consoleDict{text: map[string]string{}, prefix: map[string]string{"Fix the file:": "请修复文件："}}
	got = localizeHTML(pref, `<p>Fix the file: /etc/policy.hujson</p>`)
	if !strings.Contains(got, "请修复文件：/etc/policy.hujson") {
		t.Errorf("prefix rule did not apply:\n%s", got)
	}
	if got := translator("zh")("%d rules", 3); got != "3 条规则" {
		t.Errorf("T with arguments = %q, want 3 条规则", got)
	}
	if got := translator("en")("%d rules", 3); got != "3 rules" {
		t.Errorf("T with arguments (en) = %q, want 3 rules", got)
	}

	// English is a pass-through: the same bytes come back.
	dictEN := consoleTranslations[consoleDefaultLang]
	if dictEN.text != nil || dictEN.block != nil {
		t.Skip("English dictionary is unexpectedly populated")
	}
	if got := translateHTML("en", page); got != page {
		t.Errorf("English page changed:\n%s", got)
	}
}

// TestConsoleTimezone checks the console prints local time when the operator
// configured a zone, and UTC for an unknown one.
func TestConsoleTimezone(t *testing.T) {
	loc, err := loadConsoleTimezone("Asia/Shanghai")
	if err != nil {
		t.Skipf("zone database unavailable: %v", err)
	}
	moment := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if got, want := consoleTimeIn(moment, loc), "2026-10-08 20:00 CST"; got != want {
		t.Errorf("Shanghai time = %q, want %q", got, want)
	}

	fallback, err := loadConsoleTimezone("Nowhere/Elsewhere")
	if err == nil {
		t.Error("an unknown zone name was accepted")
	}
	if fallback != time.UTC {
		t.Errorf("unknown zone fell back to %v, want UTC", fallback)
	}
	if got := consoleTimeIn(time.Time{}, loc); got != "never" {
		t.Errorf("zero time = %q, want never", got)
	}
	if got := consoleTimeIn(moment, nil); got != "2026-10-08 12:00 UTC" {
		t.Errorf("nil location = %q, want UTC", got)
	}

	s := newServerWithConfig(t, Config{ConsoleTimezone: "UTC"})
	if got := s.consoleTime(moment); got != "2026-10-08 12:00 UTC" {
		t.Errorf("configured console time = %q, want UTC format", got)
	}
}

// TestErrorPageLocalized checks the standalone pages (errors, sign-in) follow
// the same language as the console.
func TestErrorPageLocalized(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	body := bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/login", "zh-CN,zh;q=0.9"))
	for _, want := range []string{"<h1>登录</h1>", "选择身份提供方以继续。", `<html lang="zh"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Chinese sign-in page does not contain %q:\n%s", want, body)
		}
	}

	// An error page follows the same preference, including its tab title.
	body = bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/register/unknown-link", "zh-CN,zh;q=0.9"))
	if !strings.Contains(body, `<html lang="zh"`) || !strings.Contains(body, "<title>未知登录链接") {
		t.Errorf("error page is not localized:\n%.600s", body)
	}
	if !strings.Contains(body, "返回登录") {
		t.Errorf("error page lacks the localized sign-in link:\n%.600s", body)
	}
}

// TestNotFoundPage checks the handler for unmatched paths: a browser that
// asked for HTML gets the localized page, while the API and the client
// binaries keep the plain-text reply they parse today.
func TestNotFoundPage(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	request := func(target, accept, language string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, hs.URL+target, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if language != "" {
			req.Header.Set("Accept-Language", language)
		}
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	browser := request("/no-such-page", "text/html,application/xhtml+xml", "zh-CN,zh;q=0.9")
	if browser.StatusCode != http.StatusNotFound {
		t.Errorf("browser status = %d, want 404", browser.StatusCode)
	}
	body := bodyString(t, browser)
	for _, want := range []string{`<html lang="zh"`, "未找到页面", "你访问的页面不存在。"} {
		if !strings.Contains(body, want) {
			t.Errorf("Chinese 404 page does not contain %q:\n%.400s", want, body)
		}
	}

	english := bodyString(t, request("/no-such-page", "text/html", "en-US,en;q=0.9"))
	if !strings.Contains(english, "Page not found") || !strings.Contains(english, "The page you asked for does not exist.") {
		t.Errorf("English 404 page is wrong:\n%.400s", english)
	}

	// Everything that is not a browser keeps the plain-text reply, including
	// an HTML-accepting path under /api/.
	for _, tc := range []struct{ name, target, accept string }{
		{"api client", "/no-such-page", "application/json"},
		{"no accept header", "/no-such-page", ""},
		{"unmatched api path", "/api/v2/no-such-endpoint", "text/html"},
		{"unmatched console path", "/console/no-such-page", "application/json"},
	} {
		req, err := http.NewRequest(http.MethodGet, hs.URL+tc.target, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if tc.accept != "" {
			req.Header.Set("Accept", tc.accept)
		}
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.target, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", tc.name, resp.StatusCode)
		}
		if got := string(raw); got != "404 page not found\n" {
			t.Errorf("%s body = %q, want a plain-text 404", tc.name, got)
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Errorf("%s content type = %q, want a non-HTML reply", tc.name, ct)
		}
	}

	// An unknown page under the console mount is answered by the same handler
	// as an unknown page at the root.
	if body := bodyString(t, request("/console/no-such-page", "text/html", "zh-CN,zh;q=0.9")); !strings.Contains(body, "未找到页面") {
		t.Errorf("console 404 page is not localized:\n%.400s", body)
	}
}

// TestSecurityListSeparator pins the localized separator on the security page:
// Chinese uses its own comma, English keeps the ASCII one.
func TestSecurityListSeparator(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/security")

	zh := bodyString(t, getRequestWithLanguage(t, client, hs.URL+"/console/security", "zh-CN,zh;q=0.9", cookie))
	if !strings.Contains(zh, "，") || strings.Contains(zh, "默认地图, ") {
		t.Errorf("Chinese security page keeps the ASCII list separator:\n%.600s", zh)
	}

	en := bodyString(t, getRequestWithLanguage(t, client, hs.URL+"/console/security", "en-US,en;q=0.9", cookie))
	if !strings.Contains(en, "default map, ") {
		t.Errorf("English security page lost its list separator:\n%.600s", en)
	}
}
