package ldap

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Trace is the structured report of one diagnostic authentication attempt
// (admin "LDAP" page). It exposes each step's outcome so an operator can
// see exactly where a login failed. Passwords are never recorded here.
type Trace struct {
	Mode    string `json:"mode"` // service-bind | self-bind
	OK      bool   `json:"ok"`   // final outcome
	Steps   []Step `json:"steps"`
	elapsed time.Time
}

// Step is one attempt stage.
type Step struct {
	Step   string `json:"step"` // dial_tls | bind | search | read_attrs | map_roles
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Ms     int64  `json:"ms"`
}

func (t *Trace) begin() { t.elapsed = time.Now() }

// step records one stage; ok determines OK/FAIL.
func (t *Trace) step(name string, ok bool, detail string) {
	t.Steps = append(t.Steps, Step{
		Step:   name,
		OK:     ok,
		Detail: detail,
		Ms:     time.Since(t.elapsed).Milliseconds(),
	})
	t.elapsed = time.Now()
}

// failStep records a failure and marks the whole trace failed.
func (t *Trace) failStep(name string, err error) bool {
	t.step(name, false, err.Error())
	t.OK = false
	return false
}

// Config exposes a copy of the effective settings for the admin page.
// The bind password is NEVER included (S-03/S-09).
func (c *Client) Config() Settings {
	return c.cfg
}

// TestAuth runs one authentication attempt and records every step. It is a
// diagnostic tool for the admin page: the same code paths as Authenticate
// (self-bind or service-bind), but with per-step tracing. The password is
// used for the bind only and is neither stored nor logged (S-09).
func (c *Client) TestAuth(username, password string) (*Trace, *User) {
	if c.cfg.SelfBind {
		return c.testSelfBind(username, password)
	}
	return c.testServiceBind(username, password)
}

func (c *Client) testSelfBind(username, password string) (*Trace, *User) {
	t := &Trace{Mode: "self-bind"}
	t.begin()

	attr, login := c.normalizeLogin(username)
	bindName := c.bindName(login)

	t.step("resolve_login", true, fmt.Sprintf("bind identity: %s; search attribute: %s", bindName, attr))

	conn, err := c.dial()
	if err != nil {
		t.failStep("dial_tls", err)
		return t, nil
	}
	t.step("dial_tls", true, c.cfg.URL)

	defer conn.Close()

	if err := conn.Bind(bindName, password); err != nil {
		t.failStep("bind", err)
		return t, nil
	}
	t.step("bind", true, fmt.Sprintf("bound as %s", bindName))

	filter := c.userFilter(attr, login)
	res, err := conn.Search(c.userSearchRequest(filter))
	if err != nil {
		t.failStep("search", err)
		return t, nil
	}
	if len(res.Entries) != 1 {
		t.failStep("search", fmt.Errorf("expected 1 entry, got %d (bound OK but the entry is not readable under %s)", len(res.Entries), c.cfg.BaseDN))
		return t, nil
	}
	t.step("search", true, fmt.Sprintf("found %s", res.Entries[0].DN))

	user, err := c.toUser(res.Entries[0])
	if err != nil {
		t.failStep("read_attrs", err)
		return t, nil
	}
	t.step("read_attrs", true, fmt.Sprintf("displayName=%q email=%q memberOf=%d", user.DisplayName, user.Email, len(user.MemberOf)))
	t.step("map_roles", true, fmt.Sprintf("roles=%v", user.Roles))
	t.OK = true
	return t, user
}

func (c *Client) testServiceBind(username, password string) (*Trace, *User) {
	t := &Trace{Mode: "service-bind"}
	t.begin()

	attr, login := c.normalizeLogin(username)
	t.step("resolve_login", true, fmt.Sprintf("search attribute: %s", attr))

	conn, err := c.acquire()
	if err != nil {
		t.failStep("service_bind", err)
		return t, nil
	}
	t.step("service_bind", true, c.cfg.BindDN)

	filter := c.userFilter(attr, login)
	req := c.userSearchRequest(filter)
	res, err := conn.Search(req)
	broken := err != nil && isConnBroken(err)
	c.release(conn, broken)
	if err != nil {
		t.failStep("search", err)
		return t, nil
	}
	if len(res.Entries) == 0 {
		t.failStep("search", fmt.Errorf("user not found under %s", c.cfg.BaseDN))
		return t, nil
	}
	if len(res.Entries) > 1 {
		t.failStep("search", fmt.Errorf("%d entries match (ambiguous directory)", len(res.Entries)))
		return t, nil
	}
	entry := res.Entries[0]
	t.step("search", true, fmt.Sprintf("found %s", entry.DN))

	if err := c.userBind(entry.DN, password); err != nil {
		t.failStep("user_bind", err)
		return t, nil
	}
	t.step("user_bind", true, fmt.Sprintf("bound as %s", entry.DN))

	user, err := c.toUser(entry)
	if err != nil {
		t.failStep("read_attrs", err)
		return t, nil
	}
	t.step("read_attrs", true, fmt.Sprintf("displayName=%q email=%q memberOf=%d", user.DisplayName, user.Email, len(user.MemberOf)))
	t.step("map_roles", true, fmt.Sprintf("roles=%v", user.Roles))
	t.OK = true
	return t, user
}

// userSearchRequest builds the constant-structure user search (S-01).
// userFilter builds the constant-structure search filter (S-01). When
// LDAP_OBJECT_CLASS is empty (default, mirrors the proven integrations on
// this directory) the filter matches on the login attribute only.
func (c *Client) userFilter(attr, login string) string {
	esc := ldap.EscapeFilter(login)
	if c.cfg.ObjectClass == "" {
		return fmt.Sprintf("(%s=%s)", attr, esc)
	}
	return fmt.Sprintf("(&(objectClass=%s)(%s=%s))", ldap.EscapeFilter(c.cfg.ObjectClass), attr, esc)
}

func (c *Client) userSearchRequest(filter string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter,
		[]string{"dn", c.cfg.UserAttr, c.cfg.NameAttr, c.cfg.MailAttr, "memberOf"},
		nil,
	)
}
