package policy

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/state"
)

// sshPrincipalsOf flattens the principals of a compiled policy.
func sshPrincipalsOf(pol *tailcfg.SSHPolicy) []string {
	if pol == nil {
		return nil
	}
	var out []string
	for _, rule := range pol.Rules {
		for _, p := range rule.Principals {
			out = append(out, p.NodeIP)
		}
	}
	return out
}

func TestCompileSSHPolicyAccept(t *testing.T) {
	engine := mustEngine(t, `{
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"users": ["autogroup:nonroot", "root"],
		}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	nodes := []state.Node{one, two}

	pol := engine.CompileSSHPolicy(one, nodes)
	if pol == nil || len(pol.Rules) != 1 {
		t.Fatalf("policy = %+v, want one rule", pol)
	}
	rule := pol.Rules[0]

	got := sshPrincipalsOf(pol)
	if len(got) != 4 { // both nodes, both addresses
		t.Errorf("principals = %v, want both nodes' addresses", got)
	}
	if rule.SSHUsers["*"] != "=" || rule.SSHUsers["root"] != "root" {
		t.Errorf("SSHUsers = %v, want *→= and root→root", rule.SSHUsers)
	}
	if rule.Action == nil || !rule.Action.Accept {
		t.Errorf("action = %+v, want accept", rule.Action)
	}
}

func TestCompileSSHPolicyDoesNotMatchOtherUsers(t *testing.T) {
	engine := mustEngineOpts(t, `{
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`, logins(map[tailcfg.UserID]string{1: "alice", 2: "bob"}))

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	two.UserID = 2
	nodes := []state.Node{one, two}

	got := sshPrincipalsOf(engine.CompileSSHPolicy(one, nodes))
	if len(got) != 2 || strings.Contains(strings.Join(got, ","), "100.64.0.2") {
		t.Errorf("principals = %v, want only alice's node", got)
	}
}

func TestCompileSSHPolicyDestinationSelectors(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["root"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	if pol := engine.CompileSSHPolicy(server, nodes); pol == nil || len(pol.Rules) != 1 {
		t.Errorf("the tagged server should receive an SSH policy, got %+v", pol)
	}
	if pol := engine.CompileSSHPolicy(client, nodes); pol != nil {
		t.Errorf("a non-destination node must not receive an SSH policy, got %+v", pol)
	}

	dests := engine.SSHDestinations(nodes)
	if !dests[server.ID] || dests[client.ID] {
		t.Errorf("destinations = %v, want only the tagged server", dests)
	}
}

func TestCompileSSHPolicyCheckModeIsNotEnforced(t *testing.T) {
	engine := mustEngine(t, `{
		"ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	if pol := engine.CompileSSHPolicy(one, []state.Node{one}); pol != nil {
		t.Errorf("check rules must compile to nothing, got %+v", pol)
	}
	var found bool
	for _, w := range engine.Warnings() {
		if strings.Contains(w, "ssh[0]") && strings.Contains(w, "grants nothing") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want a note that the check rule is not enforced", engine.Warnings())
	}
}

func TestSSHRuleValidation(t *testing.T) {
	bad := []struct {
		name string
		doc  string
	}{
		{"missing action", `{"ssh": [{"src": ["*"], "dst": ["*"], "users": ["root"]}]}`},
		{"unknown action", `{"ssh": [{"action": "deny", "src": ["*"], "dst": ["*"], "users": ["root"]}]}`},
		{"missing src", `{"ssh": [{"action": "accept", "dst": ["*"], "users": ["root"]}]}`},
		{"missing dst", `{"ssh": [{"action": "accept", "src": ["*"], "users": ["root"]}]}`},
		{"missing users", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"]}]}`},
		{"wildcard user", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["*"]}]}`},
		{"port in dst", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*:22"], "users": ["root"]}]}`},
		{"unknown tag in dst", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["tag:nope"], "users": ["root"]}]}`},
		{"bad acceptEnv", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"], "acceptEnv": ["FOO BAR"]}]}`},
	}

	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseString(tt.doc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := NewEngine(doc, Options{}); err == nil {
				t.Error("NewEngine accepted an invalid ssh rule")
			}
		})
	}
}
