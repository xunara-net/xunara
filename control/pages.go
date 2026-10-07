package control

import (
	"html/template"
	"net/http"
)

// pageHead is shared by every page: no external assets, no scripts, a strict
// referrer policy.
const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}} — Xunara</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; background: #f4f5f7; color: #16181d; }
main { max-width: 34rem; margin: 6vh auto; background: #fff; padding: 2rem; border-radius: .75rem;
       box-shadow: 0 1px 3px rgba(0,0,0,.12); }
h1 { font-size: 1.35rem; margin-top: 0; }
p { line-height: 1.5; }
.provider { display: block; margin: .6rem 0; padding: .7rem 1rem; background: #16181d; color: #fff;
            text-decoration: none; border-radius: .5rem; text-align: center; }
.provider:hover { background: #2b2f38; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }
dt { color: #5b616e; }
.actions { margin-top: 1.5rem; display: flex; gap: .75rem; }
button { font: inherit; padding: .7rem 1.2rem; border-radius: .5rem; border: 0; cursor: pointer; }
.approve { background: #1a7f37; color: #fff; }
.deny { background: #fff; color: #b42318; border: 1px solid #d0d5dd; }
footer { margin-top: 2rem; color: #5b616e; font-size: .8rem; }
code { background: #f1f2f4; padding: .1rem .3rem; border-radius: .25rem; }
</style>
</head>
<body><main>
`

var pageFoot = template.Must(template.New("foot").Parse(`<footer>Xunara {{.Version}}</footer></main></body></html>`))

var (
	loginPageTemplate = template.Must(template.New("login").Parse(pageHead + `
<h1>Sign in</h1>
<p>Choose an identity provider to continue.</p>
{{range .Providers}}<a class="provider" href="{{.URL}}">{{.Name}}</a>{{end}}
{{if .Passkey}}
<p><button id="passkey-signin" type="button">Sign in with a passkey</button></p>
<p id="passkey-status" class="status" role="status"></p>
{{end}}
` + `{{if .Passkey}}<script>` + passkeyBrowserJS + `
(function () {
  const button = document.getElementById("passkey-signin");
  const status = document.getElementById("passkey-status");
  button.addEventListener("click", async function () {
    button.disabled = true;
    status.textContent = "";
    try {
      const begin = await passkeyPost("/passkey/login/begin", {});
      const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(begin.options.publicKey) });
      const returnTo = new URLSearchParams(window.location.search).get("return_to");
      const url = "/passkey/login/finish" + (returnTo ? "?return_to=" + encodeURIComponent(returnTo) : "");
      const finish = await passkeyPost(url, encodeAssertion(credential));
      window.location = finish.redirect || "/";
    } catch (err) {
      status.textContent = err.message || "Passkey sign-in failed.";
      button.disabled = false;
    }
  });
})();
</script>{{end}}` + `</main></body></html>`))

	errorPageTemplate = template.Must(template.New("error").Parse(pageHead + `
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p><a href="/login">Back to sign-in</a></p>
` + `</main></body></html>`))

	approvePageTemplate = template.Must(template.New("approve").Parse(pageHead + `
<h1>Device approval</h1>
<p>A device is asking to join the tailnet. Approving authorizes the machine keys
below; it does not make the device a human identity.</p>
<dl>
<dt>Device</dt><dd>{{.Hostname}}</dd>
<dt>Operating system</dt><dd>{{.OS}}</dd>
<dt>Requested</dt><dd>{{.Created}}</dd>
<dt>Signed in as</dt><dd>{{.LoginName}}</dd>
</dl>
{{if .CanWrite}}
<form method="post" action="/register/{{.AuthID}}/approve">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="approve" type="submit">Approve device</button>
</div>
</form>
<form method="post" action="/register/{{.AuthID}}/deny">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="deny" type="submit">Deny</button>
</div>
</form>
{{else}}
<p>Your role is read-only; ask an admin or owner to approve this device.</p>
{{end}}
` + `</main></body></html>`))

	decidedPageTemplate = template.Must(template.New("decided").Parse(pageHead + `
<h1>Registration {{.State}}</h1>
<p>This device registration was already {{.State}}. You can close this window and
return to the device.</p>
` + `</main></body></html>`))

	sshCheckPageTemplate = template.Must(template.New("sshcheck").Parse(pageHead + `
<h1>SSH check</h1>
<p>A Tailscale SSH connection is waiting for a decision. Approving lets it
proceed; the decision is recorded in the audit log.</p>
<dl>
<dt>From</dt><dd>{{.Source}}</dd>
<dt>To</dt><dd>{{.Destination}}</dd>
<dt>Run as</dt><dd><code>{{.LocalUser}}</code></dd>
<dt>Requested</dt><dd>{{.Created}}</dd>
<dt>Expires</dt><dd>{{.Expires}}</dd>
<dt>Deciding as</dt><dd>{{.LoginName}}</dd>
</dl>
{{if .CanWrite}}
<form method="post" action="/ssh/check/{{.AuthID}}/approve">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="approve" type="submit">Approve connection</button>
</div>
</form>
<form method="post" action="/ssh/check/{{.AuthID}}/deny">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="deny" type="submit">Deny</button>
</div>
</form>
{{else}}
<p>Your role is read-only; ask an admin or owner to decide this connection.</p>
{{end}}
` + `</main></body></html>`))
)

// renderLoginPage lists the configured providers, and the passkey button when
// passkey sign-in is enabled.
func (s *Server) renderLoginPage(w http.ResponseWriter, providers []providerView, passkey bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginPageTemplate.Execute(w, map[string]any{
		"Title": "Sign in", "Providers": providers, "Passkey": passkey,
	}); err != nil {
		s.log.Error("rendering login page", "err", err)
	}
}

// renderError shows a plain error page. The message must be static, never
// provider- or request-controlled text.
func (s *Server) renderError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := errorPageTemplate.Execute(w, map[string]any{
		"Title": title, "Message": message,
	}); err != nil {
		s.log.Error("rendering error page", "err", err)
	}
}

// renderApprovePage shows the device approval form.
func (s *Server) renderApprovePage(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := approvePageTemplate.Execute(w, data); err != nil {
		s.log.Error("rendering approval page", "err", err)
	}
}

// renderSSHCheckPage shows the SSH check approval form.
func (s *Server) renderSSHCheckPage(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := sshCheckPageTemplate.Execute(w, data); err != nil {
		s.log.Error("rendering ssh check page", "err", err)
	}
}

// renderDecidedPage shows the outcome of a device decision.
func (s *Server) renderDecidedPage(w http.ResponseWriter, state string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := decidedPageTemplate.Execute(w, map[string]any{
		"Title": "Registration " + state,
		"State": state,
	}); err != nil {
		s.log.Error("rendering decided page", "err", err)
	}
}
