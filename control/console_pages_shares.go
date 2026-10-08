package control

// consoleSharesTemplate renders /console/shares (PROJECT_SPEC section 38.3).
// Every control on the page POSTs with the session CSRF token; the write
// guard and the share service enforce the actual authorization.
var consoleSharesTemplate = consolePage("shares", `
<h2>Machine shares</h2>
{{if not .Enabled}}
<p>Sharing is not enabled on this deployment. Cross-organization shares live
in a platform-level registry, so they are available only when the server runs
with <code>-platform-state-dir</code> and a router hosts both organizations in
this process (PROJECT_SPEC section 38.2).</p>
{{else}}
<p>Sharing a machine gives one identity in another organization a synthetic
view of that machine: addresses, node IDs and tags are never exchanged, and
only the receiving user's nodes see it (PROJECT_SPEC section 38.4). Sharing is
unavailable while either organization enforces tailnet lock.</p>

{{if .CanWrite}}
<h3>Share a machine</h3>
<form method="post" action="/console/shares">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<input name="node" list="share-nodes" required placeholder="machine ID or stable ID" aria-label="Machine">
<datalist id="share-nodes">{{range .Nodes}}<option value="{{.Ref}}">{{.Label}}</option>{{end}}</datalist>
<input name="target_organization" required placeholder="target organization ID" aria-label="Target organization">
<input name="provider" required placeholder="identity provider" aria-label="Provider">
<input name="subject" required placeholder="identity subject" aria-label="Subject">
<button type="submit">Share</button>
</div>
<p>Provider and subject identify the recipient (for example an OIDC issuer and
its <code>sub</code>); email addresses are attributes, never identity keys.</p>
</form>
{{end}}

<h3>Outgoing</h3>
{{if .Outgoing}}
<table>
<thead><tr><th>Machine</th><th>Target</th><th>Identity</th><th>Status</th><th>Created</th><th>Accepted</th>{{if .CanWrite}}<th></th>{{end}}</tr></thead>
<tbody>
{{range .Outgoing}}
<tr>
<td>{{.NodeLabel}}<br><code>{{.ID}}</code></td>
<td>{{.Counterpart}}</td>
<td><code>{{.Provider}}</code> {{.Subject}}</td>
<td>{{.Status}}{{if .RevokedBy}} by {{.RevokedBy}}{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{if .AcceptedAt}}{{fmtTime .AcceptedAt}}{{else}}—{{end}}</td>
{{if $.CanWrite}}<td>{{if .CanRevoke}}<form method="post" action="/console/shares/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Revoke</button></form>{{else}}—{{end}}</td>{{end}}
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No machines shared with other organizations.</p>
{{end}}

<h3>Incoming</h3>
{{if .Incoming}}
<table>
<thead><tr><th>Machine</th><th>Source</th><th>Identity</th><th>Status</th><th>Created</th><th>Accepted</th><th></th></tr></thead>
<tbody>
{{range .Incoming}}
<tr>
<td>{{.NodeLabel}}<br><code>{{.ID}}</code></td>
<td>{{.Counterpart}}</td>
<td><code>{{.Provider}}</code> {{.Subject}}</td>
<td>{{.Status}}{{if .RevokedBy}} by {{.RevokedBy}}{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{if .AcceptedAt}}{{fmtTime .AcceptedAt}}{{else}}—{{end}}</td>
<td>
{{if .CanAccept}}<form method="post" action="/console/shares/{{.ID}}/accept"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button type="submit">Accept</button></form>{{end}}
{{if .CanReject}}<form method="post" action="/console/shares/{{.ID}}/reject"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Reject</button></form>{{end}}
{{if .CanRevoke}}<form method="post" action="/console/shares/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Revoke</button></form>{{end}}
{{if not .CanRevoke}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No machines are shared with your identities.</p>
{{end}}
{{end}}
`)
