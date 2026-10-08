package control

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

// The console shares the sign-in pages' rules: no external assets, no scripts,
// a strict referrer policy. Every value is rendered through html/template, so
// operator-entered text (hostnames, user names, DNS values) is escaped.
// Secrets are never rendered except where a handler explicitly passes a
// one-time value such as a freshly created pre-auth key.

// siteTokens is the shared design system of the web surface: one palette with
// light and dark values, system fonts only, and no external assets. Both the
// console shell and the sign-in pages build on it so the whole flow looks the
// same; page-specific rules follow the token block in each page's <style>.
const siteTokens = `
:root {
  color-scheme: light dark;
  --bg: #f4f6f8; --surface: #ffffff; --surface-2: #f1f3f6;
  --fg: #15181e; --muted: #59606d;
  --border: #e2e6ec; --border-2: #c9d1dc;
  --accent: #1f5fd8; --accent-fg: #ffffff; --accent-soft: #e8f0fe;
  --ok: #1a7f37; --ok-bg: #e6f4ea;
  --warn: #b42318; --warn-bg: #fdecec;
  --shadow: 0 1px 2px rgba(16, 24, 40, .05), 0 2px 6px rgba(16, 24, 40, .06);
  --radius: 10px; --radius-sm: 7px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --wrap: 76rem;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #101318; --surface: #171b22; --surface-2: #1e232c;
    --fg: #e8eaf0; --muted: #9aa4b2;
    --border: #272d38; --border-2: #38414f;
    --accent: #7aa2ff; --accent-fg: #0d1117; --accent-soft: #1a2333;
    --ok: #6bd08a; --ok-bg: #12291c;
    --warn: #ff9a90; --warn-bg: #31181a;
    --shadow: 0 1px 2px rgba(0, 0, 0, .35), 0 2px 8px rgba(0, 0, 0, .3);
  }
}
:root[data-theme="dark"] {
  --bg: #101318; --surface: #171b22; --surface-2: #1e232c;
  --fg: #e8eaf0; --muted: #9aa4b2;
  --border: #272d38; --border-2: #38414f;
  --accent: #7aa2ff; --accent-fg: #0d1117; --accent-soft: #1a2333;
  --ok: #6bd08a; --ok-bg: #12291c;
  --warn: #ff9a90; --warn-bg: #31181a;
  --shadow: 0 1px 2px rgba(0, 0, 0, .35), 0 2px 8px rgba(0, 0, 0, .3);
}
* { box-sizing: border-box; }
`

const consoleHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}} — Xunara console</title>
<style>` + siteTokens + `
body { font-family: var(--font); margin: 0; background: var(--bg); color: var(--fg);
       line-height: 1.5; -webkit-text-size-adjust: 100%; }
.skip { position: absolute; left: -999px; top: 0; z-index: 100; background: var(--surface);
        color: var(--fg); padding: .6rem .9rem; border-radius: 0 0 var(--radius-sm) 0; }
.skip:focus { left: 0; }
.topbar { position: sticky; top: 0; z-index: 50; display: flex; flex-wrap: wrap; align-items: center;
          gap: .35rem .9rem; padding: .7rem 1.4rem; background: var(--surface);
          border-bottom: 1px solid var(--border); }
.brand { font-size: 1rem; font-weight: 700; letter-spacing: .01em; display: flex; align-items: baseline; gap: .4rem; }
.brand span { color: var(--muted); font-weight: 500; }
nav { display: flex; flex-wrap: wrap; gap: .15rem; }
nav a { color: var(--muted); text-decoration: none; padding: .35rem .55rem; border-radius: var(--radius-sm);
        font-size: .86rem; font-weight: 500; }
nav a:hover { background: var(--surface-2); color: var(--fg); }
nav a.active { background: var(--accent); color: var(--accent-fg); }
.who { margin-left: auto; display: flex; align-items: center; gap: .5rem; font-size: .84rem; color: var(--muted); }
.who form { margin: 0; }
.who-name { font-weight: 600; color: var(--fg); }
main { max-width: var(--wrap); margin: 1.4rem auto 3rem; padding: 0 1.4rem; }
main:focus { outline: none; }
h2 { font-size: 1.2rem; margin: 1.9rem 0 .6rem; letter-spacing: -.01em; }
h3 { font-size: 1rem; margin: 1.3rem 0 .4rem; }
h2:first-child, h3:first-child { margin-top: .4rem; }
h2 + p, h3 + p { margin-top: .2rem; }
p { margin: .5rem 0; }
a { color: var(--accent); }
.table-wrap { overflow-x: auto; margin: .6rem 0 1rem; background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--radius); box-shadow: var(--shadow); }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top;
         overflow-wrap: anywhere; }
th { background: var(--surface-2); color: var(--muted); font-size: .78rem; font-weight: 600;
     text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
tbody tr:hover td { background: var(--surface-2); }
tr:last-child td { border-bottom: 0; }
.table-filter { display: block; width: 100%; max-width: 22rem; margin: .7rem 0 0; font: inherit;
                padding: .45rem .6rem; border: 1px solid var(--border-2); border-radius: var(--radius-sm);
                background: var(--surface); color: var(--fg); }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(9.5rem, 1fr)); gap: .7rem;
         margin: 1rem 0 1.6rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
        padding: .85rem 1rem; box-shadow: var(--shadow); display: flex; flex-direction: column; gap: .15rem; }
.card .num { font-size: 1.45rem; font-weight: 650; letter-spacing: -.01em; }
.card span:last-child { color: var(--muted); font-size: .82rem; }
.ok { color: var(--ok); font-weight: 600; }
.off { color: var(--muted); }
.warn { color: var(--warn); font-weight: 600; }
.tag { display: inline-block; background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);
       border-radius: 999px; padding: .05rem .45rem; font-size: .72rem; font-weight: 600; }
.tag.warn { color: var(--warn); background: var(--warn-bg); border-color: currentColor; }
.notice { background: var(--ok-bg); border: 1px solid var(--border); border-color: var(--ok);
          color: var(--fg); padding: .6rem .9rem; border-radius: var(--radius-sm); margin: .6rem 0; }
.notice.warn { background: var(--warn-bg); border-color: var(--warn); }
input:not([type="hidden"]):not([type="checkbox"]) { font: inherit; padding: .4rem .55rem;
  border: 1px solid var(--border-2); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); }
input::placeholder { color: var(--muted); }
a:focus-visible, input:focus-visible, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
button { font: inherit; font-size: .86rem; font-weight: 600; padding: .4rem .75rem;
         border: 1px solid transparent; border-radius: var(--radius-sm); cursor: pointer;
         background: var(--accent); color: var(--accent-fg); }
button:hover { filter: brightness(1.06); }
button.ghost { background: transparent; color: var(--muted); border-color: var(--border-2); }
button.ghost:hover { color: var(--fg); background: var(--surface-2); }
button.danger { background: transparent; color: var(--warn); border-color: var(--warn); }
button + button { margin-left: .3rem; }
code { font-family: var(--mono); font-size: .82em; background: var(--surface-2); border: 1px solid var(--border);
       padding: .05rem .3rem; border-radius: 5px; }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: .75rem; overflow-x: auto; font-size: .82rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1.1rem; margin: .6rem 0 1rem; }
dt { color: var(--muted); }
dd { margin: 0; }
.field { display: flex; gap: .6rem; align-items: center; margin: .55rem 0; flex-wrap: wrap; }
.field label { color: var(--muted); font-size: .86rem; }
footer { text-align: center; color: var(--muted); font-size: .78rem; padding: 1.5rem 1rem 2rem; }
.sr-only { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden;
           clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.nav-toggle, .theme-toggle { display: none; }
html.js .theme-toggle { display: inline-flex; align-items: center; background: transparent; color: var(--muted);
  border: 1px solid var(--border-2); padding: .3rem .5rem; }
@media (max-width: 860px) {
  .topbar { padding: .6rem .9rem; }
  html.js .nav-toggle { display: inline-flex; align-items: center; background: transparent; color: var(--muted);
    border: 1px solid var(--border-2); padding: .3rem .6rem; }
  html.js #console-nav { display: none; flex-direction: column; width: 100%; order: 9; }
  html.js .topbar.nav-open #console-nav { display: flex; }
  nav a { padding: .55rem .6rem; }
  main { padding: 0 .9rem; margin-top: 1rem; }
  dl { grid-template-columns: 1fr; gap: .1rem; }
  dt { margin-top: .5rem; }
  h2 { font-size: 1.1rem; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
<span class="brand">Xunara <span>console</span></span>
<button class="nav-toggle" type="button" aria-expanded="false" aria-controls="console-nav" hidden>Menu</button>
<nav id="console-nav" aria-label="Console sections">
<a href="/console/"{{if eq .Nav "overview"}} class="active" aria-current="page"{{end}}>Overview</a>
<a href="/console/machines"{{if eq .Nav "machines"}} class="active" aria-current="page"{{end}}>Machines</a>
<a href="/console/exit-nodes"{{if eq .Nav "exit-nodes"}} class="active" aria-current="page"{{end}}>Exit nodes</a>
<a href="/console/services"{{if eq .Nav "services"}} class="active" aria-current="page"{{end}}>Services</a>
<a href="/console/relays"{{if eq .Nav "relays"}} class="active" aria-current="page"{{end}}>Relays</a>
<a href="/console/serve"{{if eq .Nav "serve"}} class="active" aria-current="page"{{end}}>Serve</a>
<a href="/console/devices"{{if eq .Nav "devices"}} class="active" aria-current="page"{{end}}>Devices</a>
<a href="/console/users"{{if eq .Nav "users"}} class="active" aria-current="page"{{end}}>Users</a>
<a href="/console/passkeys"{{if eq .Nav "passkeys"}} class="active" aria-current="page"{{end}}>Passkeys</a>
<a href="/console/dns"{{if eq .Nav "dns"}} class="active" aria-current="page"{{end}}>DNS</a>
<a href="/console/derp"{{if eq .Nav "derp"}} class="active" aria-current="page"{{end}}>DERP</a>
<a href="/console/auth-keys"{{if eq .Nav "auth-keys"}} class="active" aria-current="page"{{end}}>Auth keys</a>
<a href="/console/agents"{{if eq .Nav "agents"}} class="active" aria-current="page"{{end}}>Agents</a>
<a href="/console/api-keys"{{if eq .Nav "api-keys"}} class="active" aria-current="page"{{end}}>API keys</a>
<a href="/console/shares"{{if eq .Nav "shares"}} class="active" aria-current="page"{{end}}>Shares</a>
<a href="/console/reach"{{if eq .Nav "reach"}} class="active" aria-current="page"{{end}}>Reach</a>
<a href="/console/flux"{{if eq .Nav "flux"}} class="active" aria-current="page"{{end}}>Flux</a>
<a href="/console/ssh-check"{{if eq .Nav "ssh-check"}} class="active" aria-current="page"{{end}}>SSH checks</a>
<a href="/console/webhooks"{{if eq .Nav "webhooks"}} class="active" aria-current="page"{{end}}>Webhooks</a>
<a href="/console/policy"{{if eq .Nav "policy"}} class="active" aria-current="page"{{end}}>Policy</a>
<a href="/console/security"{{if eq .Nav "security"}} class="active" aria-current="page"{{end}}>Security</a>
<a href="/console/audit"{{if eq .Nav "audit"}} class="active" aria-current="page"{{end}}>Audit</a>
</nav>
<div class="who"><span class="who-name">{{.User}}</span> <span class="tag">{{.Role}}</span>
<button class="theme-toggle" type="button" hidden aria-label="Switch color theme">◐</button>
<form method="post" action="/logout"><button class="ghost" type="submit">Sign out</button></form>
</div>
</header>
<main id="main" tabindex="-1">
{{if not .CanWrite}}<p class="notice">Your role is read-only; controls that change the tailnet are hidden.</p>{{end}}
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
`

const consoleFoot = `</main>
<footer>Xunara {{.Version}}</footer>
<script>` + consoleJS + `</script>
</body></html>`

// consoleJS is the console's progressive enhancement: the pages work without
// JavaScript, and this adds a persisted dark-mode toggle, a collapsible mobile
// nav, scrollable tables with a row filter, and a confirmation for destructive
// submissions. It is inline like the passkey ceremony, so the console keeps
// its no-external-assets rule, and it never receives server data.
const consoleJS = `
(function () {
  var root = document.documentElement;
  root.classList.add("js");

  function preferredTheme() {
    var stored = null;
    try { stored = localStorage.getItem("xunara-theme"); } catch (err) { stored = null; }
    if (stored === "dark" || stored === "light") return stored;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  var themeButton = document.querySelector(".theme-toggle");
  if (themeButton) {
    themeButton.hidden = false;
    var label = function () {
      var next = preferredTheme() === "dark" ? "light" : "dark";
      themeButton.textContent = next === "dark" ? "\u263e" : "\u2600";
      themeButton.setAttribute("aria-label", "Switch to " + next + " theme");
      themeButton.title = themeButton.getAttribute("aria-label");
    };
    label();
    themeButton.addEventListener("click", function () {
      var next = preferredTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("xunara-theme", next); } catch (err) {}
      label();
    });
  }

  var navToggle = document.querySelector(".nav-toggle");
  var topbar = document.querySelector(".topbar");
  if (navToggle && topbar) {
    navToggle.hidden = false;
    navToggle.addEventListener("click", function () {
      var open = topbar.classList.toggle("nav-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll("main table"), function (table) {
    if (table.parentElement && table.parentElement.className === "table-wrap") return;
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
    if (!table.tBodies.length || table.tBodies[0].rows.length < 6) return;
    var box = document.createElement("input");
    box.type = "search";
    box.className = "table-filter";
    box.placeholder = "Filter rows\u2026";
    box.setAttribute("aria-label", "Filter table rows");
    wrap.parentNode.insertBefore(box, wrap);
    box.addEventListener("input", function () {
      var needle = box.value.toLowerCase();
      Array.prototype.forEach.call(table.tBodies, function (body) {
        Array.prototype.forEach.call(body.rows, function (row) {
          row.hidden = needle !== "" && row.textContent.toLowerCase().indexOf(needle) < 0;
        });
      });
    });
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || form.dataset.confirm === "skip") return;
    var danger = form.querySelector("button.danger");
    if (!danger) return;
    var verb = danger.textContent.trim() || "Confirm";
    if (!window.confirm(verb + " \u2014 are you sure?")) event.preventDefault();
  });
})();
`

// consoleTitles label each section; the nav identifier doubles as the key so a
// handler cannot forget to set a page title.
var consoleTitles = map[string]string{
	"overview":   "Overview",
	"machines":   "Machines",
	"exit-nodes": "Exit nodes",
	"services":   "Services",
	"relays":     "Relays",
	"serve":      "Serve",
	"devices":    "Devices",
	"users":      "Users",
	"passkeys":   "Passkeys",
	"dns":        "DNS",
	"derp":       "DERP",
	"auth-keys":  "Auth keys",
	"agents":     "Agents",
	"api-keys":   "API keys",
	"shares":     "Shares",
	"reach":      "Reach",
	"flux":       "Flux",
	"ssh-check":  "SSH checks",
	"webhooks":   "Webhooks",
	"policy":     "Policy",
	"security":   "Security",
	"audit":      "Audit",
}

// consolePage assembles a console template from the shared shell and a body.
func consolePage(name, body string) *template.Template {
	tmpl := template.New(name).Funcs(template.FuncMap{
		"fmtTime":  consoleTime,
		"argvLine": consoleArgvLine,
		"join":     func(values []string) string { return strings.Join(values, ", ") },
	})
	return template.Must(tmpl.Parse(consoleHead + body + consoleFoot))
}

// consoleArgvPreviewLimit bounds the one-line argv preview on the Reach list.
const consoleArgvPreviewLimit = 120

// consoleArgvLine renders a one-line command preview: the same argv the agent
// executed, joined with spaces and cut on a rune boundary. The session page
// shows every argument on its own.
func consoleArgvLine(argv []string) string {
	line := strings.Join(argv, " ")
	runes := []rune(line)
	if len(runes) > consoleArgvPreviewLimit {
		return string(runes[:consoleArgvPreviewLimit]) + "…"
	}
	return line
}

// consoleTime formats a timestamp; the zero time reads as "never".
func consoleTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

var (
	consoleOverviewTemplate = consolePage("overview", `
<h2>Overview</h2>
<div class="cards">
<div class="card"><span class="num">{{.MachinesOnline}}</span><span>machines online</span></div>
<div class="card"><span class="num">{{.MachinesTotal}}</span><span>machines total</span></div>
<div class="card"><span class="num">{{.Users}}</span><span>users</span></div>
<div class="card"><span class="num">{{.PendingDevices}}</span><span>pending devices</span></div>
<div class="card"><span class="num">{{.DNSRecords}}</span><span>DNS records</span></div>
<div class="card"><span class="num">{{.AuthKeys}}</span><span>auth keys</span></div>
<div class="card"><span class="num">{{.Agents}}</span><span>agent credentials</span></div>
</div>
<h2>Access control</h2>
<p>{{.Policy}}</p>
<h2>Tailnet lock</h2>
{{if .TailnetLock.Enabled}}
<p><span class="ok">enabled</span> — chain head <code>{{.TailnetLock.Head}}</code>;
{{.TailnetLock.Nodes.Signed}} of {{.TailnetLock.Nodes.Total}} nodes carry a node-key
signature, so peers verify every node key without trusting this control plane.</p>
{{else if .TailnetLock.Disabled}}
<p><span class="warn">disabled</span> — the chain is kept, so a node that still
enforces tailnet lock locally can fetch the disablement secret and clear its
state. Node keys are no longer verified by peers.</p>
{{else}}
<p>Not enabled. Node keys are not verified by peers; an administrator turns it on
with <code>tailscale lock init</code> from a trusted machine.</p>
{{end}}
<h2>Workload identity</h2>
{{if .IDTokenError}}
<p><span class="warn">unavailable</span> — {{.IDTokenError}}</p>
{{else if .IDToken.Enabled}}
<p><span class="ok">issuer enabled</span> — nodes fetch identity tokens at
<code>{{.IDToken.Issuer}}</code>/machine/id-token; relying parties verify them with the
public keys at <code>{{.IDToken.JWKSURL}}</code>.</p>
<p>{{len .IDToken.Keys}} signing key(s) published; the active key is
<code>{{.IDToken.ActiveKeyID}}</code>. Issued tokens are valid for
{{.IDToken.TokenTTLSeconds}} seconds and name the requesting node, never another one.
Rotate the key with <code>xunara id-token rotate</code>.</p>
{{else}}
<p>Not enabled: this deployment has no externally reachable <code>-server-url</code>,
so it has no issuer URL to be a trust anchor for, and nodes receive 501 from
<code>/machine/id-token</code>.</p>
{{end}}
`)

	consoleMachinesTemplate = consolePage("machines", `
<h2>Machines</h2>
<table>
<thead><tr><th scope="col">Machine</th><th scope="col">Status</th><th scope="col">Owner</th><th scope="col">Method</th><th scope="col">Addresses</th><th scope="col">Routes</th><th scope="col">Posture</th><th scope="col">Services</th><th scope="col">Actions</th></tr></thead>
<tbody>
{{range .Machines}}
<tr>
<td>{{.Hostname}}
{{if .Ephemeral}} <span class="tag">ephemeral</span>{{end}}
{{if .ExitNode}} <span class="tag">exit node</span>{{end}}
{{if .Expired}} <span class="tag warn">expired</span>{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{.UserLoginName}}</td>
<td>{{.Method}}</td>
<td>{{if .IPv4}}<code>{{.IPv4}}</code>{{end}}{{if .IPv6}}<br><code>{{.IPv6}}</code>{{end}}</td>
<td>
{{if .ApprovedRoutes}}approved: {{range .ApprovedRoutes}}<code>{{.}}</code> {{end}}<br>{{end}}
{{if .AnnouncedRoutes}}announced: {{range .AnnouncedRoutes}}<code>{{.}}</code> {{end}}{{else}}announced: none{{end}}
</td>
<td>{{if .DeviceAttrCount}}{{.DeviceAttrCount}} attr{{if ne .DeviceAttrCount 1}}s{{end}}{{else}}—{{end}}</td>
<td>{{if .ServiceCount}}{{.ServiceCount}}{{else}}—{{end}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/machines/{{.ID}}/routes">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button name="action" value="approve-all" type="submit">Approve routes</button>
<button name="action" value="unapprove-all" type="submit">Withdraw</button>
</form>
<form method="post" action="/console/machines/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{else}}
<tr><td colspan="9">No machines have registered yet.</td></tr>
{{end}}
</tbody>
</table>
`)

	consoleDevicesTemplate = consolePage("devices", `
<h2>Pending devices</h2>
<p>Approving a device authorizes the machine keys below; it does not make the
device a human identity.</p>
{{if .Devices}}
<table>
<thead><tr><th scope="col">Device</th><th scope="col">Operating system</th><th scope="col">Requested</th><th scope="col">Expires</th><th scope="col">Actions</th></tr></thead>
<tbody>
{{range .Devices}}
<tr>
<td>{{.Hostname}}</td>
<td>{{.OS}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{fmtTime .Expires}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/devices/{{.ID}}/approve">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button type="submit">Approve</button>
</form>
<form method="post" action="/console/devices/{{.ID}}/deny">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Deny</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No devices are waiting for approval.</p>
{{end}}
`)

	consoleUsersTemplate = consolePage("users", `
<h2>Users</h2>
<table>
<thead><tr><th scope="col">Login name</th><th scope="col">Display name</th><th scope="col">Role</th><th scope="col">Email</th><th scope="col">Created</th><th scope="col">Identities</th></tr></thead>
<tbody>
{{range .Users}}
<tr>
<td>{{.LoginName}}</td>
<td>{{.DisplayName}}</td>
<td>{{.Role}}</td>
<td>{{if .Email}}{{.Email}}{{else}}—{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{range .Identities}}<code>{{.ProviderID}}</code> {{.Subject}}<br>{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
<h2>Edit a user</h2>
<p>Email is an attribute, never an identity key: links follow
(provider, subject) only.{{if not .IsOwner}} Only an owner may change roles.{{end}}</p>
{{range .Users}}
{{if $.CanWrite}}
<form method="post" action="/console/users/{{.ID}}">
<h3>{{.LoginName}}</h3>
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<div class="field">
<label>Display name <input name="displayName" value="{{.DisplayName}}"></label>
<label>Email <input name="email" value="{{.Email}}"></label>
{{if $.IsOwner}}
<label>Role <select name="role">
<option value="member"{{if eq .Role "member"}} selected{{end}}>member</option>
<option value="admin"{{if eq .Role "admin"}} selected{{end}}>admin</option>
<option value="owner"{{if eq .Role "owner"}} selected{{end}}>owner</option>
</select></label>
{{end}}
<button type="submit">Save</button>
</div>
</form>
{{end}}
{{end}}
`)

	consoleDNSTemplate = consolePage("dns", `
<h2>DNS records</h2>
<p>Extra records served to clients alongside MagicDNS.</p>
{{if .Records}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Value</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Records}}
<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Type}}</td>
<td>{{.Value}}</td>
<td>{{fmtTime .Created}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/dns/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No extra DNS records.</p>
{{end}}
`)

	consoleAuthKeysTemplate = consolePage("auth-keys", `
<h2>Auth keys</h2>
<p>Pre-authentication keys let a machine register without a browser. The secret
is shown once, at creation time, and never again.</p>
{{if .CreatedKey}}
<p class="notice">New key (copy it now): <code>{{.CreatedKey}}</code></p>
{{end}}
{{if .CanWrite}}
<form method="post" action="/console/auth-keys">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<label>Lifetime <input name="ttl" placeholder="24h (empty: never)"></label>
<label>Tags <input name="tags" placeholder="tag:server, tag:prod"></label>
<label><input type="checkbox" name="reusable"> Reusable</label>
<label><input type="checkbox" name="ephemeral"> Ephemeral</label>
<button type="submit">Create key</button>
</div>
</form>
{{end}}
{{if .AuthKeys}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Owner</th><th scope="col">Tags</th><th scope="col">Reusable</th><th scope="col">Ephemeral</th><th scope="col">Used</th><th scope="col">Expires</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .AuthKeys}}
<tr>
<td>{{.ID}}</td>
<td>{{.Owner}}</td>
<td>{{if .Tags}}{{range .Tags}}<code>{{.}}</code> {{end}}{{else}}—{{end}}</td>
<td>{{if .Reusable}}yes{{else}}no{{end}}</td>
<td>{{if .Ephemeral}}yes{{else}}no{{end}}</td>
<td>{{if .Used}}yes{{else}}no{{end}}</td>
<td>{{fmtTime .Expiry}}</td>
<td>{{fmtTime .Created}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/auth-keys/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Revoke</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No auth keys.</p>
{{end}}
`)

	consoleAgentsTemplate = consolePage("agents", `
<h2>Agents</h2>
<p>Xunara Agent credentials (native clients). Revoking one signs that agent out
immediately; the device keeps its node identity and can enroll again.</p>
{{if .Tokens}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Node</th><th scope="col">Hostname</th><th scope="col">Live</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">Revoked</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Tokens}}
<tr>
<td><code>{{.ID}}</code></td>
<td>{{.NodeID}}</td>
<td>{{if .NodeHostname}}{{.NodeHostname}}{{else}}<em>deleted</em>{{end}}</td>
<td>{{if .Live}}yes{{else}}no{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{if .ExpiresAt}}{{fmtTime .ExpiresAt}}{{else}}never{{end}}</td>
<td>{{if .LastUsedAt}}{{fmtTime .LastUsedAt}}{{else}}never{{end}}</td>
<td>{{if .RevokedAt}}{{fmtTime .RevokedAt}}{{else}}—{{end}}</td>
<td>
{{if and $.CanWrite (not .RevokedAt)}}
<form method="post" action="/console/agents/{{.ID}}/revoke">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Revoke</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No agent credentials. A device creates one when it enrolls with
<code>/api/agent/v1/enroll</code>.</p>
{{end}}
`)

	consolePasskeysTemplate = consolePage("passkeys", `
<h2>Passkeys</h2>
<p>Passkeys sign you in without a password and never authorize a machine. The
private key stays on your device; the server stores only its public key.</p>
{{if .PasskeyEnabled}}
<div class="field">
<label for="passkey-name">Name</label>
<input id="passkey-name" type="text" maxlength="64" placeholder="Laptop Touch ID">
<button id="passkey-add" type="button" data-csrf="{{.CSRF}}">Add passkey</button>
</div>
<p id="passkey-status" role="status"></p>
{{else}}
<p class="notice">Passkey sign-in is not configured on this server.</p>
{{end}}
{{if .Passkeys}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Created</th><th scope="col">Last used</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Passkeys}}
<tr>
<td>{{.Name}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{fmtTime .LastUsed}}</td>
<td>
<form method="post" action="/console/passkeys/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No passkeys registered on this account.</p>
{{end}}
{{if .PasskeyEnabled}}<script>`+passkeyBrowserJS+`
(function () {
  const button = document.getElementById("passkey-add");
  const nameInput = document.getElementById("passkey-name");
  const status = document.getElementById("passkey-status");
  const csrf = button.dataset.csrf;
  button.addEventListener("click", async function () {
    button.disabled = true;
    status.textContent = "";
    try {
      const begin = await passkeyPost("/console/passkeys/begin", {}, csrf);
      const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(begin.options.publicKey) });
      await passkeyPost("/console/passkeys/finish", { name: nameInput.value, credential: encodeAttestation(credential) }, csrf);
      window.location.reload();
    } catch (err) {
      status.textContent = err.message || "Adding the passkey failed.";
      button.disabled = false;
    }
  });
})();
</script>{{end}}
`)

	consoleServicesTemplate = consolePage("services", `
<h2>Services</h2>
<p>Services nodes advertise about themselves. Publishing happens on the node
(<code>/api/agent/v1/services</code>); this page is read-only. A service name
resolves in MagicDNS to the advertising node, and reachability is still decided
by the ACL rules — discovery is not authorization. Services with health
reporting enabled are withdrawn from MagicDNS while they are unhealthy, and
<em>visibility</em> narrows which nodes can resolve the name (<code>*</code> is
the whole organization). <em>Shared</em> services are also projected into the
organizations that accepted a share of the advertising machine, under
<code>&lt;name&gt;-&lt;org&gt;</code> (discovery only: the ACL rules of both
organizations still decide who may connect). A service whose
<em>visibility</em> comes <em>from the ACL</em> is discoverable exactly by the
nodes that may already connect to it.</p>
{{if .Services}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Protocol</th><th scope="col">Port</th><th scope="col">DNS name</th><th scope="col">Visibility</th><th scope="col">Shared</th><th scope="col">Health</th><th scope="col">Node</th><th scope="col">Updated</th><th scope="col">Metadata</th></tr></thead>
<tbody>
{{range .Services}}
<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Protocol}}</td>
<td>{{.Port}}</td>
<td>{{if .DNSName}}<code>{{.DNSName}}</code>{{else}}—{{end}}</td>
<td>{{if .VisibilityFromACL}}acl{{else}}{{join .Visibility}}{{end}}</td>
<td>{{if .Shared}}yes{{else}}—{{end}}</td>
<td>{{if .Health}}{{.Health}}{{else}}—{{end}}</td>
<td>{{.Hostname}} <code>{{.StableID}}</code></td>
<td>{{fmtTime .Updated}}</td>
<td>{{if .Metadata}}{{range $k, $v := .Metadata}}<code>{{$k}}={{$v}}</code> {{end}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No services have been advertised. An agent publishes them with
<code>xunara-agent</code> / <code>/api/agent/v1/services</code>.</p>
{{end}}
`)

	consoleAPIKeysTemplate = consolePage("api-keys", `
<h2>API keys</h2>
<p>Service identity credentials for automation: the <code>xunara_…</code> tokens
<code>/api/v1</code> and <code>/api/v2</code> accept. A key carries the scopes
it was granted, but never more than its owner's role allows; only the token's
hash is stored, and this page never shows it again. OAuth/OIDC login providers
are server configuration and are not managed here.</p>
{{if .CreatedToken}}
<p class="notice">New API key created. Copy the token now — it cannot be shown
again:</p>
<pre>{{.CreatedToken}}</pre>
{{end}}
{{if .CanWrite}}
<h3>Create a key</h3>
<form method="post" action="/console/api-keys">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<label for="api-key-name">Name</label>
<input id="api-key-name" name="name" required placeholder="ci-deploy">
<label><input type="checkbox" name="scope_read" value="1" checked> read</label>
<label><input type="checkbox" name="scope_write" value="1"> write</label>
<label for="api-key-ttl">Lifetime</label>
<input id="api-key-ttl" name="ttl" placeholder="720h (empty = no expiry)">
<button type="submit">Create key</button>
</div>
</form>
{{end}}
{{if .Keys}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Owner</th><th scope="col">Scopes</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">State</th>{{if .CanWrite}}<th scope="col"></th>{{end}}</tr></thead>
<tbody>
{{range .Keys}}
<tr>
<td>{{.Name}}<br><code>{{.ID}}</code></td>
<td>{{.Owner}}</td>
<td>{{range .Scopes}}<span class="tag">{{.}}</span> {{end}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{if .Expires}}{{fmtTime .Expires}}{{else}}never{{end}}</td>
<td>{{if .LastUsed}}{{fmtTime .LastUsed}}{{else}}never{{end}}</td>
<td>{{if .Revoked}}<span class="warn">revoked {{fmtTime .Revoked}}</span>{{else}}<span class="ok">live</span>{{end}}</td>
{{if $.CanWrite}}<td>{{if not .Revoked}}<form method="post" action="/console/api-keys/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Revoke</button></form>{{end}}</td>{{end}}
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No API keys yet.</p>
{{end}}
`)

	consoleWebhooksTemplate = consolePage("webhooks", `
<h2>Webhooks</h2>
<p>Audit events are POSTed to these receivers. The signing secret is stored
sealed and is never shown again after creation.</p>
{{if .Webhooks}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">URL</th><th scope="col">Events</th><th scope="col">State</th><th scope="col">Source</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Webhooks}}
<tr>
<td><code>{{.ID}}</code></td>
<td>{{.URL}}</td>
<td>{{if .Events}}{{range .Events}}<span class="tag">{{.}}</span> {{end}}{{else}}all{{end}}</td>
<td>{{if .Enabled}}<span class="ok">enabled</span>{{else}}<span class="off">paused</span>{{end}}</td>
<td>{{.Source}}</td>
<td>{{if .Created}}{{fmtTime .Created}}{{else}}—{{end}}</td>
<td>
{{if and $.CanWrite (eq .Source "managed")}}
<form method="post" action="/console/webhooks/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else if eq .Source "config"}}from startup config{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No webhook receivers are configured.</p>
{{end}}
{{if .CanWrite}}
<h3>Add a receiver</h3>
<form method="post" action="/console/webhooks">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<div class="field"><label for="webhook-id">ID</label>
<input id="webhook-id" name="id" required></div>
<div class="field"><label for="webhook-url">URL</label>
<input id="webhook-url" name="url" size="48" placeholder="https://example.com/hooks/xunara" required></div>
<div class="field"><label for="webhook-secret">Secret</label>
<input id="webhook-secret" name="secret" type="password" required></div>
<div class="field"><label for="webhook-events">Events</label>
<input id="webhook-events" name="events" placeholder="* (all)"></div>
<button type="submit">Create webhook</button>
</form>
{{end}}
`)

	consoleFluxTemplate = consolePage("flux", `
<h2>Flux</h2>
<p>Xunara Flux file transfers between agents. The control plane relays
ciphertext only: file content and keys are end-to-end encrypted and are not
visible here or anywhere else on the server. The recipient must accept a
transfer before anything is uploaded; this page is read-only.</p>
{{if not .Enabled}}
<p>Flux is not enabled on this deployment, so there are no transfers to show.
An operator enables it with <code>-flux</code> (single organization) or
<code>flux_enabled</code> (organization table).</p>
{{else}}
<form method="get" action="/console/flux">
<div class="field"><label for="flux-state">State</label>
<select id="flux-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Transfers}}
<table>
<thead><tr><th scope="col">Created</th><th scope="col">State</th><th scope="col">File</th><th scope="col">Size</th><th scope="col">Sender</th><th scope="col">Recipient</th><th scope="col">Note</th></tr></thead>
<tbody>
{{range .Transfers}}
<tr>
<td><a href="/console/flux/{{.ID}}">{{fmtTime .CreatedAt}}</a></td>
<td>{{.State}}</td>
<td><code>{{.Name}}</code></td>
<td>{{.Size}} B</td>
<td>{{.Sender.Hostname}}<br><code>{{.Sender.StableID}}</code></td>
<td>{{.Recipient.Hostname}}<br><code>{{.Recipient.StableID}}</code></td>
<td>{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>Only the newest {{len .Transfers}} transfers are shown; filter by
state or use the API to page through the rest.</p>{{end}}
{{else}}
<p>No Flux transfers match.</p>
{{end}}
{{end}}
`)

	consoleFluxTransferTemplate = consolePage("flux", `
<h2>Flux transfer</h2>
{{if not .Enabled}}
<p>Flux is not enabled on this deployment, so there are no transfers to show.</p>
{{else}}{{with .Transfer}}
<dl>
<dt>ID</dt><dd><code>{{.ID}}</code></dd>
<dt>State</dt><dd>{{.State}}</dd>
<dt>File</dt><dd><code>{{.Name}}</code> ({{.Size}} bytes)</dd>
<dt>Sender</dt><dd>{{.Sender.Hostname}} <code>{{.Sender.StableID}}</code></dd>
<dt>Recipient</dt><dd>{{.Recipient.Hostname}} <code>{{.Recipient.StableID}}</code></dd>
<dt>SHA-256</dt><dd><code>{{.SHA256}}</code></dd>
{{if .Reason}}<dt>Note</dt><dd class="warn">{{.Reason}}</dd>{{end}}
<dt>Created</dt><dd>{{fmtTime .CreatedAt}}</dd>
<dt>Updated</dt><dd>{{fmtTime .UpdatedAt}}</dd>
<dt>Expires</dt><dd>{{fmtTime .ExpiresAt}}</dd>
</dl>
<p>The file itself is end-to-end encrypted between the two agents: the control
plane stores only ciphertext while a transfer is in flight, deletes it when
the transfer completes or fails, and no console page can show the content.</p>
{{else}}
<p>No Flux transfer has that ID.</p>
{{end}}{{end}}
`)

	consoleReachTemplate = consolePage("reach", `
<h2>Reach</h2>
<p>Xunara Reach sessions between nodes: who offered which command to which
node, how it ended, and how much output it produced. A command runs on the
target only after that node approves the offer, and only the two participants
can drive a session; this page is read-only. The audit log records the
decisions, never the command line or the output.</p>
{{if not .Enabled}}
<p>Reach is not enabled on this deployment, so no sessions can exist. An
operator enables it per organization (<code>reach_enabled</code>) and runs
<code>xunarad -reach</code>.</p>
{{else}}
<form method="get" action="/console/reach">
<div class="field"><label for="reach-state">State</label>
<select id="reach-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Sessions}}
<table>
<thead><tr><th scope="col">Created</th><th scope="col">State</th><th scope="col">Sender</th><th scope="col">Target</th><th scope="col">Command</th><th scope="col">stdout / stderr</th><th scope="col">Exit</th></tr></thead>
<tbody>
{{range .Sessions}}
<tr>
<td><a href="/console/reach/{{.ID}}">{{fmtTime .CreatedAt}}</a></td>
<td>{{.State}}</td>
<td>{{.Sender.Hostname}}<br><code>{{.Sender.StableID}}</code></td>
<td>{{.Target.Hostname}}<br><code>{{.Target.StableID}}</code></td>
<td><code>{{argvLine .Argv}}</code></td>
<td>{{.OutputBytes.Stdout}} B / {{.OutputBytes.Stderr}} B</td>
<td>{{if .ExitCode}}{{.ExitCode}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>Only the newest {{len .Sessions}} sessions are shown; filter by
state or use the API to page through the rest.</p>{{end}}
{{else}}
<p>No Reach sessions match.</p>
{{end}}
{{end}}
`)

	consoleReachSessionTemplate = consolePage("reach", `
<h2>Reach session</h2>
{{if not .Enabled}}
<p>Reach is not enabled on this deployment, so there are no sessions to show.</p>
{{else}}{{with .Session}}
<dl>
<dt>ID</dt><dd><code>{{.ID}}</code></dd>
<dt>State</dt><dd>{{.State}}</dd>
<dt>Sender</dt><dd>{{.Sender.Hostname}} <code>{{.Sender.StableID}}</code></dd>
<dt>Target</dt><dd>{{.Target.Hostname}} <code>{{.Target.StableID}}</code></dd>
<dt>Command</dt><dd>{{range .Argv}}<code>{{.}}</code> {{end}}</dd>
<dt>Timeout</dt><dd>{{.TimeoutSec}}s</dd>
<dt>Exit code</dt><dd>{{if .ExitCode}}{{.ExitCode}}{{else}}—{{end}}</dd>
{{if .Error}}<dt>Error</dt><dd class="warn">{{.Error}}</dd>{{end}}
<dt>Created</dt><dd>{{fmtTime .CreatedAt}}</dd>
<dt>Updated</dt><dd>{{fmtTime .UpdatedAt}}</dd>
<dt>Expires</dt><dd>{{fmtTime .ExpiresAt}}</dd>
<dt>Output</dt><dd>{{.OutputBytes.Stdout}} bytes on stdout, {{.OutputBytes.Stderr}} bytes on stderr</dd>
</dl>
<p>The output is retained with the session (one hour after the last update)
and may contain sensitive data; it never enters the audit log.</p>
<h3>stdout</h3>
{{if $.TruncatedOut}}<p class="warn">Showing the first {{$.OutputLimit}} bytes;
more output was written.</p>{{end}}
{{if $.Stdout}}<pre>{{$.Stdout}}</pre>{{else}}<p>No stdout output.</p>{{end}}
<h3>stderr</h3>
{{if $.TruncatedErr}}<p class="warn">Showing the first {{$.OutputLimit}} bytes;
more output was written.</p>{{end}}
{{if $.Stderr}}<pre>{{$.Stderr}}</pre>{{else}}<p>No stderr output.</p>{{end}}
{{else}}
<p>No Reach session has that ID.</p>
{{end}}{{end}}
`)

	consoleDERPTemplate = consolePage("derp", `
<h2>DERP</h2>
<p>Which DERP regions this organization serves its clients, and where the
machines are homed. The policy comes from the deployment's
<code>-derp-policy</code> / organization table; this page is read-only.
Serving a filtered map is advisory - the admission controller is the
enforceable half, and it only covers the relay Xunara runs.</p>
<dl>
<dt>Policy</dt><dd><code>{{.Status.PolicyMode}}</code>{{if eq .Status.PolicyMode "inherit"}} — the configured map is served unchanged{{end}}{{if eq .Status.PolicyMode "none"}} — clients are told this organization has no DERP{{end}}</dd>
{{if .Status.PolicyRegions}}<dt>Allowed regions</dt><dd>{{range .Status.PolicyRegions}}<code>{{.}}</code> {{end}}</dd>{{end}}
<dt>Map</dt><dd>{{if .Status.MapConfigured}}configured{{else}}not configured — clients keep their built-in default regions{{end}}</dd>
<dt>Regions served</dt><dd>{{.Status.RegionsServed}}</dd>
<dt>Machines</dt><dd>{{len .Nodes}} total; {{.Status.NodesWithoutHome}} without a home region; {{.Status.NodesWithUnservedHome}} homed to a region no longer served</dd>
</dl>
{{if .Status.Regions}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Code</th><th scope="col">Name</th><th scope="col">Relays</th><th scope="col">Machines</th></tr></thead>
<tbody>
{{range .Status.Regions}}
<tr>
<td>{{.ID}}</td>
<td>{{if .Code}}<code>{{.Code}}</code>{{else}}—{{end}}</td>
<td>{{if .Name}}{{.Name}}{{else}}—{{end}}</td>
<td>{{if .Hosts}}{{range .Hosts}}<code>{{.}}</code> {{end}}{{else}}—{{end}}</td>
<td>{{.NodeCount}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else if .Status.MapConfigured}}
<p>No regions are served: the policy tells clients this organization has no
DERP at all.</p>
{{else}}
<p>No DERP map is configured, so clients keep their built-in default regions
until one is.</p>
{{end}}
<h3>Machine placement</h3>
{{if .Nodes}}
<table>
<thead><tr><th scope="col">Machine</th><th scope="col">Status</th><th scope="col">Home region</th></tr></thead>
<tbody>
{{range .Nodes}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{if .Unserved}}<span class="warn">region {{.Home}} (no longer served)</span>{{else if .Home}}{{.Home}}{{else}}<span class="off">none chosen yet</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No machines yet.</p>
{{end}}
`)

	consolePolicyTemplate = consolePage("policy", `
<h2>Policy</h2>
{{with .View}}
{{if not .Configured}}
<p>No policy document is configured: every machine may reach every other
machine, the same behaviour as an official tailnet without a policy.</p>
{{else}}
<p>Read-only view (Xunara Warden) of the ACL document in force. It is loaded
from disk and reloaded when the file changes; there is no editor here.</p>
<dl>
<dt>Document</dt><dd><code>{{.Path}}</code></dd>
<dt>Compiled rules</dt><dd>{{.RuleCount}}</dd>
</dl>
{{if .LoadError}}<p class="warn">The file on disk no longer parses, so the previous policy is still in force: {{.LoadError}}</p>{{end}}
{{if .Warnings}}<h3>Warnings</h3><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Unsupported}}<h3>Unsupported fields</h3>
<p>These top-level fields are understood but not enforced by this build;
ignoring them can only tighten the policy, never widen it.</p>
<ul>{{range .Unsupported}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}

<h3>Traffic rules</h3>
{{if .ACLs}}
<table>
<thead><tr><th scope="col">Action</th><th scope="col">Proto</th><th scope="col">Source</th><th scope="col">Destination</th></tr></thead>
<tbody>
{{range .ACLs}}<tr>
<td>{{.Action}}</td>
<td>{{if .Proto}}{{.Proto}}{{else}}default set{{end}}</td>
<td>{{join .Src}}{{if .Users}}{{join .Users}}{{end}}</td>
<td>{{join .Dst}}{{if .Ports}}{{join .Ports}}{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No ACL rules in the document.</p>{{end}}

<h3>Grants</h3>
{{if .Grants}}
<table>
<thead><tr><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocols / ports</th><th scope="col">App capabilities</th></tr></thead>
<tbody>
{{range .Grants}}<tr>
<td>{{join .Src}}</td>
<td>{{join .Dst}}</td>
<td>{{join .IP}}</td>
<td>{{range $cap, $values := .App}}<code>{{$cap}}</code> {{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No grants in the document.</p>{{end}}

<h3>Groups</h3>
{{if .Groups}}
<table>
<thead><tr><th scope="col">Group</th><th scope="col">Members</th></tr></thead>
<tbody>
{{range $name, $members := .Groups}}<tr><td><code>{{$name}}</code></td><td>{{join $members}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No groups defined.</p>{{end}}

<h3>Hosts</h3>
{{if .Hosts}}
<table>
<thead><tr><th scope="col">Alias</th><th scope="col">Value</th></tr></thead>
<tbody>
{{range $alias, $value := .Hosts}}<tr><td><code>{{$alias}}</code></td><td><code>{{$value}}</code></td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No hosts defined.</p>{{end}}

<h3>Tag owners</h3>
{{if .TagOwners}}
<table>
<thead><tr><th scope="col">Tag</th><th scope="col">Owners</th></tr></thead>
<tbody>
{{range $tag, $owners := .TagOwners}}<tr><td><code>{{$tag}}</code></td><td>{{join $owners}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No tag owners defined.</p>{{end}}

<h3>SSH rules</h3>
{{if .SSH}}
<table>
<thead><tr><th scope="col">Action</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Users</th><th scope="col">Environment</th><th scope="col">Check period</th></tr></thead>
<tbody>
{{range .SSH}}<tr>
<td>{{.Action}}</td>
<td>{{join .Src}}</td>
<td>{{join .Dst}}</td>
<td>{{join .Users}}</td>
<td>{{if .AcceptEnv}}{{join .AcceptEnv}}{{else}}—{{end}}</td>
<td>{{if .CheckPeriod}}{{.CheckPeriod}}{{else}}12h default{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No SSH rules in the document.</p>{{end}}

<h3>Node attributes</h3>
{{if .NodeAttrs}}
<table>
<thead><tr><th scope="col">Target</th><th scope="col">Attributes</th></tr></thead>
<tbody>
{{range .NodeAttrs}}<tr><td>{{join .Target}}</td><td>{{join .Attr}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No nodeAttrs in the document.</p>{{end}}

<h3>Policy tests</h3>
{{if .Tests.Results}}
<table>
<thead><tr><th scope="col">#</th><th scope="col">Source</th><th scope="col">Proto</th><th scope="col">Result</th></tr></thead>
<tbody>
{{range .Tests.Results}}<tr>
<td>{{.Index}}</td>
<td><code>{{.Src}}</code></td>
<td>{{if .Proto}}{{.Proto}}{{else}}default set{{end}}</td>
<td>{{if .Pass}}<span class="ok">pass</span>{{else}}<span class="warn">fail</span><ul>{{range .Failures}}<li>{{.}}</li>{{end}}</ul>{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>Not run ({{.Tests.Total}} in the document){{if .Tests.Reason}}: {{.Tests.Reason}}{{end}}.</p>{{end}}
{{end}}
{{end}}
`)

	consoleSSHCheckTemplate = consolePage("ssh-check", `
<h2>SSH checks</h2>
<p>Tailscale SSH "check" mode: connections held until a human decides. This
page is read-only. A verdict is handed to exactly one follow-up request, so
"consumed" means the connection that asked for it already took the verdict;
"expired" is a pending check whose TTL passed before the janitor removed it.</p>
<form method="get" action="/console/ssh-check">
<div class="field"><label for="ssh-check-state">State</label>
<select id="ssh-check-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Sessions}}
<table>
<thead><tr><th scope="col">Check</th><th scope="col">State</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Local user</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Verdict</th></tr></thead>
<tbody>
{{range .Sessions}}
<tr>
<td><a href="/ssh/check/{{.ID}}"><code>{{.ID}}</code></a></td>
<td>{{if eq .State "pending"}}<span class="ok">pending</span>{{else}}{{.State}}{{end}}</td>
<td>{{if .Src.Hostname}}{{.Src.Hostname}}<br>{{end}}<code>node {{.Src.NodeID}}</code>{{if .Src.StableID}} <code>{{.Src.StableID}}</code>{{end}}</td>
<td>{{if .Dst.Hostname}}{{.Dst.Hostname}}<br>{{end}}<code>node {{.Dst.NodeID}}</code>{{if .Dst.StableID}} <code>{{.Dst.StableID}}</code>{{end}}</td>
<td>{{if .LocalUser}}<code>{{.LocalUser}}</code>{{else}}—{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{fmtTime .ExpiresAt}}</td>
<td>{{.Verdict}}{{if .DecidedBy}} by {{.DecidedBy.LoginName}}{{end}}{{if .ConsumedAt}}<br>consumed {{fmtTime .ConsumedAt}}{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>Only the newest {{len .Sessions}} sessions are shown; filter by
state or use the API to page through the rest.</p>{{end}}
{{else}}
<p>No SSH checks match.</p>
{{end}}
`)

	consoleAuditTemplate = consolePage("audit", `
<h2>Audit</h2>
<p>The most recent events first, at most 200.</p>
{{if .Events}}
<table>
<thead><tr><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Detail</th></tr></thead>
<tbody>
{{range .Events}}
<tr>
<td>{{fmtTime .Time}}</td>
<td>{{.Actor}}</td>
<td><code>{{.Action}}</code></td>
<td>{{.Target}}</td>
<td>{{.Detail}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No audit events yet.</p>
{{end}}
`)
)

// renderConsole writes a console page. Console output is per-session state and
// must never be cached by shared caches.
func (s *Server) renderConsole(w http.ResponseWriter, tmpl *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := tmpl.Execute(w, data); err != nil {
		s.log.Error("rendering console page", "template", tmpl.Name(), "err", err)
	}
}
