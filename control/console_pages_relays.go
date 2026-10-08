package control

// consoleRelaysTemplate renders /console/relays (PROJECT_SPEC section 42):
// which nodes offer to relay, which grants authorize relays, and where the
// two do not line up. The page is read-only.
var consoleRelaysTemplate = consolePage("relays", `
<h2>Relays</h2>
<p>Peer relays are an underlay mesh extension: a node with
<code>tailscale set --relay-server-port=…</code> offers to relay UDP traffic
for other nodes, and an ACL grant carrying
<code>tailscale.com/cap/relay</code> authorizes which nodes may allocate relay
endpoints from it. Clients fall back to a relay only when direct connectivity
and DERP are not good enough; the control plane never selects one.</p>

<h3>Relay candidates</h3>
{{if .View.Relays}}
<table>
<thead><tr><th scope="col">Node</th><th scope="col">Owner</th><th scope="col">Status</th><th scope="col">Offering</th><th scope="col">Grant</th></tr></thead>
<tbody>
{{range .View.Relays}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Owner}}<span translate="no">{{.Owner}}</span>{{else}}—{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{if .Announced}}<span class="ok">offers relay</span>{{else}}<span class="tag warn">no relay offer</span>{{end}}
{{if .Disabled}} <span class="tag warn">disable-relay-server</span>{{end}}
{{if .ClientDisabled}} <span class="tag warn">disable-relay-client</span>{{end}}</td>
<td>{{if .Targeted}}named by a relay grant{{else}}<span class="off">not in any relay grant</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No node offers to relay. A node opts in with
<code>tailscale set --relay-server-port=&lt;port&gt;</code>; its willingness then
appears here, and a relay grant decides who may use it.</p>
{{end}}

<h3>Relay grants</h3>
{{if .View.Grants}}
<table>
<thead><tr><th scope="col">Sources</th><th scope="col">Relay targets</th></tr></thead>
<tbody>
{{range .View.Grants}}
<tr>
<td>{{range .Sources}}{{.Hostname}} <span class="off" translate="no">({{.Owner}})</span>
{{if .ClientDisabled}}<span class="tag warn">disable-relay-client</span>{{end}}<br>{{end}}</td>
<td>{{range .Targets}}{{.Hostname}} <span class="off" translate="no">({{.Owner}})</span>
{{if not .Announced}}<span class="tag warn">no relay offer</span>{{end}}
{{if .Disabled}}<span class="tag warn">disable-relay-server</span>{{end}}<br>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
<p class="off">A grant authorizes allocation; a target that does not offer a
relay, or is disabled by policy, is a configuration mismatch to fix.</p>
{{else}}
<p>A relay grant is a <code>grants</code> row whose <code>app</code> map
carries <code>tailscale.com/cap/relay</code>, for example
<code>{"src": ["group:dev"], "dst": ["tag:relay"],
"app": {"tailscale.com/cap/relay": []}}</code>. Nothing is authorized
until such a row exists.</p>
{{end}}
`)
