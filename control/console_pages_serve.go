package control

// consoleServeTemplate renders /console/serve (PROJECT_SPEC section 43): who
// may serve HTTPS, whether certificates can be issued, and where Funnel was
// reported even though this control plane does not run public ingress. The
// page is read-only.
var consoleServeTemplate = consolePage("serve", `
<h2>Serve</h2>
<p><code>tailscale serve</code> runs on the device. It needs the
<code>https</code> node attribute from the policy, and a certificate: this
control plane proxies ACME DNS-01 challenges to the configured DNS provider,
so the device must be able to obtain one of the names below. Nothing here is
changed from this page.</p>

<p>Certificates:
{{if .View.Certificates}}<span class="ok">DNS provider configured</span>
{{else}}<span class="tag warn">not available</span> — no DNS provider is
configured, so devices cannot complete an ACME challenge and report
certificates as unsupported.{{end}}</p>
{{if .View.CertDomains}}<p>Extra certificate domains:
{{range .View.CertDomains}}<code>{{.}}</code> {{end}}</p>{{end}}

<p>Funnel: <span class="tag warn">not supported</span>. Funnel needs public
ingress infrastructure this build does not run; the policy loader rejects the
<code>funnel</code> attribute outright, and a device that still reports Funnel
endpoints enabled is shown below as a misconfiguration.</p>

{{if .View.Nodes}}
<table>
<thead><tr><th scope="col">Node</th><th scope="col">Owner</th><th scope="col">Status</th><th scope="col">Serve</th><th scope="col">Certificates</th><th scope="col">Funnel</th></tr></thead>
<tbody>
{{range .View.Nodes}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Owner}}{{.Owner}}{{else}}—{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{if .Serve}}<span class="ok">https granted</span>{{else}}<span class="off">not granted</span>{{end}}</td>
<td>{{if .CertDomains}}{{range .CertDomains}}<code>{{.}}</code><br>{{end}}{{else}}<span class="off">none</span>{{end}}</td>
<td>{{if .Funnel}}<span class="tag warn">funnel reported</span>{{else}}—{{end}}
{{if .WantsIngress}}<br><span class="off">requests ingress wiring</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No device is authorized to serve, and none reported Funnel or ingress
activity. Grant <code>https</code> in the policy's <code>nodeAttrs</code> to
enable <code>tailscale serve</code> on a device.</p>
{{end}}
`)
