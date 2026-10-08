package control

// The tenant's commercial page (PROJECT_SPEC section 54): which plan this
// tailnet is on, what it allows, what it uses, and the network range its
// devices are allocated from. It is read-only — moving a tailnet to another
// plan is the platform operator's decision — but it is the page a member opens
// to understand why a device was refused.

var consolePlanTemplate = consolePage("plan", `
{{if .PlanKnown}}
<h2>{{T "Current plan"}}</h2>
<dl>
<dt>{{T "Plan"}}</dt><dd>{{.PlanName}} <code>{{.PlanID}}</code></dd>
<dt>{{T "Devices"}}</dt><dd>{{.DevicesUsed}} / {{.DeviceAllowance}}</dd>
<dt>{{T "Users"}}</dt><dd>{{.UsersUsed}} / {{.UserAllowance}}</dd>
<dt>{{T "Network range"}}</dt><dd><code>{{.NetworkPrefix}}</code></dd>
{{if .NetworkManaged}}<dt></dt><dd>{{T "This range is assigned automatically; the plan decides whether it can be changed."}}</dd>{{end}}
</dl>
<h2>{{T "What this plan includes"}}</h2>
<div class="table-wrap"><table>
<thead><tr><th>{{T "Capability"}}</th><th>{{T "Included"}}</th><th>{{T "Limit"}}</th></tr></thead>
<tbody>
<tr><td>{{T "Devices"}}</td><td>{{.Feature.Devices}}</td><td>{{.DeviceAllowance}}</td></tr>
<tr><td>{{T "Members"}}</td><td>{{.Feature.Users}}</td><td>{{.UserAllowance}}</td></tr>
<tr><td>{{T "Subnet routers"}}</td><td>{{.Feature.SubnetRouter}}</td><td>{{.RouteAllowance}}</td></tr>
<tr><td>{{T "Exit nodes"}}</td><td>{{.Feature.ExitNode}}</td><td>—</td></tr>
<tr><td>{{T "Custom network range"}}</td><td>{{.Feature.CustomCIDR}}</td><td>—</td></tr>
<tr><td>{{T "API keys"}}</td><td>{{.Feature.API}}</td><td>—</td></tr>
<tr><td>{{T "Multi-member tailnet"}}</td><td>{{.Feature.Members}}</td><td>{{.UserAllowance}}</td></tr>
<tr><td>{{T "Audit log"}}</td><td>{{.Feature.Audit}}</td><td>—</td></tr>
</tbody>
</table></div>
{{if .QuotaReached}}<p class="notice warn">{{T "A quota of this plan has been reached; new devices or members are refused until the plan changes."}}</p>{{end}}
{{else}}
<p class="notice">{{T "This deployment does not sell plans: every quota is unlimited, and this page has nothing to report."}}</p>
{{end}}
`)
