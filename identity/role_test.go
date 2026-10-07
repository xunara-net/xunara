package identity

import "testing"

func TestParseRole(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    Role
		wantErr bool
	}{
		{"member", RoleMember, false},
		{"Admin", RoleAdmin, false},
		{" OWNER ", RoleOwner, false},
		{"", "", true},
		{"root", "", true},
		{"administrator", "", true},
	} {
		got, err := ParseRole(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseRole(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseRole(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestRoleCapabilities(t *testing.T) {
	for _, tt := range []struct {
		role     Role
		canWrite bool
		isOwner  bool
		isValid  bool
	}{
		{RoleMember, false, false, true},
		{RoleAdmin, true, false, true},
		{RoleOwner, true, true, true},
		{Role("root"), false, false, false},
		{Role(""), false, false, false},
	} {
		if got := tt.role.CanWrite(); got != tt.canWrite {
			t.Errorf("%q.CanWrite() = %v, want %v", tt.role, got, tt.canWrite)
		}
		if got := tt.role.IsOwner(); got != tt.isOwner {
			t.Errorf("%q.IsOwner() = %v, want %v", tt.role, got, tt.isOwner)
		}
		if got := tt.role.Valid(); got != tt.isValid {
			t.Errorf("%q.Valid() = %v, want %v", tt.role, got, tt.isValid)
		}
	}
}
