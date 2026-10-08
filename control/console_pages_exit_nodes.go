package control

// consoleExitNodesTemplate renders /console/exit-nodes (PROJECT_SPEC section
// 40): the approved exit nodes and the clients that selected each one. The
// page is read-only; approval stays on the machines page and selection is a
// client-local preference.
var consoleExitNodesTemplate = consolePage("exit-nodes", `
<h2>Exit nodes</h2>
<p>An exit node is a machine approved to route the tailnet's default routes.
Nodes choose one locally (<code>tailscale up --exit-node=…</code>), and the
client reports that choice to the control plane; this page joins the two
halves. Approval and withdrawal live on the Machines page.</p>

<h3>Approved exit nodes</h3>
{{if .View.ExitNodes}}
<table>
<thead><tr><th>Node</th><th>Owner</th><th>Status</th><th>Addresses</th><th>DERP home</th><th>Clients</th></tr></thead>
<tbody>
{{range .View.ExitNodes}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Owner}}{{.Owner}}{{else}}—{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}
{{if not .Announced}} <span class="tag warn">not advertising</span>{{end}}</td>
<td>{{if .IPv4}}<code>{{.IPv4}}</code>{{end}}{{if .IPv6}}<br><code>{{.IPv6}}</code>{{end}}</td>
<td>{{if .DERPHome}}{{.DERPHome}}{{else}}—{{end}}</td>
<td>{{if .ClientCount}}{{.ClientCount}}{{else}}none{{end}}
{{range .Clients}}<br>{{.Hostname}} <span class="off">({{.Owner}})</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No machine is approved as an exit node. Approve the default route on the
Machines page after the node advertises <code>0.0.0.0/0</code> and/or
<code>::/0</code>.</p>
{{end}}

<h3>Clients</h3>
<p>Every node that reported an exit-node selection. A selection that no longer
names an approved exit node stays listed as unresolved: approving or restoring
the node makes it effective again.</p>
{{if .View.Clients}}
<table>
<thead><tr><th>Node</th><th>Owner</th><th>Status</th><th>Selected exit node</th><th>State</th></tr></thead>
<tbody>
{{range .View.Clients}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Owner}}{{.Owner}}{{else}}—{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{if .ExitNodeHostname}}{{.ExitNodeHostname}}{{else}}<span class="off">unknown node</span>{{end}}<br><code>{{.ExitNodeStableID}}</code></td>
<td>{{if .Resolved}}<span class="ok">in effect</span>{{else}}<span class="warn">unresolved</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No node has selected an exit node.</p>
{{end}}
`)
