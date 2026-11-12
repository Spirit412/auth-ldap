package ldap

import (
	"errors"
	"testing"
)

func TestMapRoles(t *testing.T) {
	admin := "CN=aps-admins,OU=groups,DC=mca,DC=local"
	cases := []struct {
		name     string
		memberOf []string
		adminDN  string
		want     []string
	}{
		{"admin exact", []string{"CN=Users", admin}, admin, []string{"admin"}},
		{"admin case-insensitive", []string{"cn=aps-admins,ou=groups,dc=mca,dc=local"}, admin, []string{"admin"}},
		{"admin spaces trimmed", []string{"  " + admin + " "}, admin, []string{"admin"}},
		{"no admin group", []string{"CN=Users"}, admin, []string{}},
		{"no membership", nil, admin, []string{}},
		{"admin dn empty", []string{admin}, "", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRoles(tc.memberOf, tc.adminDN)
			if len(got) != len(tc.want) {
				t.Fatalf("roles = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("roles = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// S-01: the filter template must contain exactly one value placeholder and
// the escaping is provided by ldap.EscapeFilter; ensure the structure is
// constant (no raw concatenation of user input outside the placeholder).
func TestFilterTemplateStructure(t *testing.T) {
	if filterTemplate != "(&(objectClass=person)(%s=%s))" {
		t.Fatalf("filter template changed unexpectedly: %q", filterTemplate)
	}
}

func TestNewRejectsBadCAFile(t *testing.T) {
	_, err := New(Settings{URL: "ldaps://localhost:636", CAFile: "does-not-exist.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestDummyBindDNIsValidStructure(t *testing.T) {
	// S-08: the dummy DN must look plausible enough for a server to reject
	// the bind (same error class as a real user bind failure).
	if dummyBindDN == "" || len(dummyBindDN) < 10 {
		t.Fatalf("dummy DN too short: %q", dummyBindDN)
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	if errors.Is(ErrInvalidCredentials, ErrUnavailable) {
		t.Fatal("sentinel errors must be distinct (401 vs 503 mapping)")
	}
}
