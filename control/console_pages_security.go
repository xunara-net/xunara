package control

// consoleSecurityTemplate renders /console/security (PROJECT_SPEC section
// 39): a snapshot of the tailnet's security posture and the findings derived
// from it. The page is read-only and shows no key material.
var consoleSecurityTemplate = consolePage("security", `
<h2>Security</h2>
<p>A snapshot of this tailnet's security posture, derived from the state the
other management surfaces already own. There is deliberately no score and no
live monitoring: findings are deterministic observations (spec section 39).</p>

<div class="cards">
<div class="card"><span class="num">{{if .View.TailnetLock.Enabled}}on{{else}}off{{end}}</span><span>tailnet lock</span></div>
<div class="card"><span class="num">{{if .View.Policy.Configured}}{{.View.Policy.RuleCount}}{{else}}allow-all{{end}}</span><span>policy rules</span></div>
<div class="card"><span class="num">{{.View.Nodes.Total}}</span><span>nodes</span></div>
<div class="card"><span class="num">{{.View.Nodes.Unsigned}}</span><span>unsigned nodes</span></div>
<div class="card"><span class="num">{{.View.Nodes.Expired}}</span><span>expired keys</span></div>
<div class="card"><span class="num">{{.View.Devices.Pending}}</span><span>pending devices</span></div>
<div class="card"><span class="num">{{.View.APIKeys.Live}}</span><span>live API keys</span></div>
<div class="card"><span class="num">{{if .View.Sharing.Enabled}}{{.View.Sharing.IncomingPending}}{{else}}off{{end}}</span><span>incoming share invites</span></div>
</div>

<h3>Findings</h3>
{{if .View.Findings}}
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>
{{range .View.Findings}}
<tr>
<td>{{if eq .Severity "high"}}<span class="warn">high</span>{{else if eq .Severity "medium"}}<span class="tag warn">medium</span>{{else if eq .Severity "low"}}<span class="tag">low</span>{{else}}<span class="off">info</span>{{end}}</td>
<td><code>{{.ID}}</code><br>{{.Title}}</td>
<td>{{.Detail}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No findings: the posture matches the configured expectations.</p>
{{end}}

<h3>Node keys</h3>
<p>Every node whose key expiry is set, soonest first. Expired and expiring
keys are the actionable subset; the rest is the schedule.</p>
{{if .Expiry}}
<table>
<thead><tr><th>Node</th><th>Owner</th><th>Expires</th><th>State</th></tr></thead>
<tbody>
{{range .Expiry}}
<tr>
<td>{{.Hostname}}</td>
<td>{{if .Owner}}{{.Owner}}{{else}}—{{end}}</td>
<td>{{fmtTime .Expiry}}</td>
<td>{{if eq .State "expired"}}<span class="warn">expired</span>{{else if eq .State "expiring"}}<span class="tag warn">expiring</span>{{else}}scheduled{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No node keys expire; every node is registered without a key expiry.</p>
{{end}}

<h3>Components</h3>
<dl>
<dt>Tailnet lock</dt><dd>{{if .View.TailnetLock.Enabled}}enforced{{else if .View.TailnetLock.Disabled}}disabled (chain kept){{else}}never enabled{{end}}</dd>
<dt>Policy</dt><dd>{{if .View.Policy.Configured}}{{.View.Policy.RuleCount}} rule(s), {{.View.Policy.WarningCount}} warning(s){{else}}not configured (allow-all){{end}}</dd>
<dt>Auth keys</dt><dd>{{.View.AuthKeys.Total}} total, {{.View.AuthKeys.Expired}} expired, {{.View.AuthKeys.Unused}} unused single-use</dd>
<dt>API keys</dt><dd>{{.View.APIKeys.Live}} live, {{.View.APIKeys.Revoked}} revoked, {{.View.APIKeys.Expired}} expired, {{.View.APIKeys.NeverExpires}} without expiry</dd>
<dt>Sharing</dt><dd>{{if .View.Sharing.Enabled}}outgoing {{.View.Sharing.OutgoingPending}} pending / {{.View.Sharing.OutgoingAccepted}} accepted; incoming {{.View.Sharing.IncomingPending}} pending / {{.View.Sharing.IncomingAccepted}} accepted{{else}}not enabled{{end}}</dd>
<dt>Webhooks</dt><dd>{{if .View.Webhooks.Enabled}}delivering ({{.View.Webhooks.Configured}} configured, {{.View.Webhooks.ManagedActive}} managed, {{.View.Webhooks.ManagedPaused}} paused){{else}}not delivering{{end}}</dd>
<dt>DERP</dt><dd>{{if .View.DERP.MapConfigured}}map configured{{else}}default map{{end}}, policy {{if .View.DERP.Policy}}{{.View.DERP.Policy}}{{else}}open{{end}}, {{.View.DERP.RegionsServed}} region(s)</dd>
</dl>
`)
