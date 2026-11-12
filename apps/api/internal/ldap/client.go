// Package ldap implements the AD client: LDAPS connectivity, user search
// with filter escaping, password verification by user Bind, and role
// mapping from group membership.
//
// Security decisions:
//   - S-01: every user-supplied value interpolated into a filter goes
//     through ldap.EscapeFilter; the filter structure is a constant
//     template, never raw string concatenation.
//   - S-02: only ldaps:// (or ldap:// + StartTLS); tls.Config validates the
//     server certificate against a CA bundle unless LDAP_TLS_INSECURE is
//     explicitly enabled (test mode with mock LDAP only, logged loudly).
//   - S-03: the service account is read-only (bind + search), never a
//     Domain Admin.
//   - S-08: when the user does not exist we perform a dummy bind against a
//     fixed DN with the attacker-supplied password so that response timing
//     matches the "wrong password" path (user-enumeration defence).
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Sentinel errors mapped to HTTP statuses by the API layer:
//
//	ErrInvalidCredentials -> 401, ErrUnavailable -> 503 (fail-closed, S-07).
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnavailable        = errors.New("ldap unavailable")
	ErrAmbiguousUser      = errors.New("ambiguous user")
)

// User is the authenticated identity produced by Authenticate.
type User struct {
	DN          string
	Username    string
	DisplayName string
	Email       string
	MemberOf    []string
	Roles       []string
}

// Settings is the subset of app config needed here (kept local so this
// package has no dependency on the config package).
type Settings struct {
	URL           string // ldaps://host:636
	StartTLS      bool   // for ldap:// URLs
	CAFile        string
	InsecureTLS   bool
	BindDN        string
	BindPassword  string
	BaseDN        string
	ObjectClass   string // AD: person; simple mocks: inetOrgPerson
	NetBIOSDomain string // self-bind: DOMAIN\user bind name
	SelfBind      bool   // no service account: bind AS the user
	UserAttr      string
	NameAttr      string
	MailAttr      string
	AdminGroupDN  string
	UPNSuffix     string // enables user@suffix -> userPrincipalName search
	PoolSize      int
	Timeout       time.Duration
	Retry         int
}

// dummyBindDN is a syntactically valid but never-existing DN used to burn
// one bind attempt on the "unknown user" path (S-08 timing alignment).
const dummyBindDN = "CN=aps-dummy-nonexistent,CN=Users,DC=invalid"

// Client is a small connection pool of TLS connections bound to the
// read-only service account.
type Client struct {
	cfg     Settings
	tlsConf *tls.Config

	mu   sync.Mutex
	idle []*ldap.Conn
	sem  chan struct{} // bounds concurrent connections
}

// New validates settings and prepares the TLS configuration.
func New(cfg Settings) (*Client, error) {
	if cfg.PoolSize < 1 {
		cfg.PoolSize = 1
	}
	if cfg.Retry < 1 {
		cfg.Retry = 1
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// S-02: InsecureSkipVerify is a deliberate, explicit test-mode
		// escape hatch for the mock LDAP. It must never be enabled in prod.
		InsecureSkipVerify: cfg.InsecureTLS,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read LDAP_CA_CERT_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("LDAP_CA_CERT_FILE contains no usable certificates")
		}
		tlsConf.RootCAs = pool
	}
	if cfg.BindDN == "" || cfg.BindPassword == "" {
		cfg.SelfBind = true
	}
	return &Client{
		cfg:     cfg,
		tlsConf: tlsConf,
		sem:     make(chan struct{}, cfg.PoolSize),
	}, nil
}

// dial opens one TLS connection. Retries transient failures with
// exponential backoff (reliability requirement: LDAP temporary unavailability).
func (c *Client) dial() (*ldap.Conn, error) {
	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < c.cfg.Retry; attempt++ {
		conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(c.tlsConf))
		if err == nil {
			conn.SetTimeout(c.cfg.Timeout)
			if c.cfg.StartTLS {
				// ldap:// must be upgraded before any bind (S-02).
				if err := conn.StartTLS(c.tlsConf); err != nil {
					conn.Close()
					return nil, err
				}
			}
			return conn, nil
		}
		lastErr = err
		time.Sleep(backoff)
		backoff *= 2
	}
	return nil, lastErr
}

// acquire returns a connection bound to the service account, reusing an
// idle one from the pool when possible.
func (c *Client) acquire() (*ldap.Conn, error) {
	c.sem <- struct{}{}
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		conn := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()

	conn, err := c.dial()
	if err != nil {
		<-c.sem
		return nil, err
	}
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		conn.Close()
		<-c.sem
		return nil, err
	}
	return conn, nil
}

// release returns the connection to the pool, dropping broken ones.
func (c *Client) release(conn *ldap.Conn, broken bool) {
	if broken || conn == nil {
		if conn != nil {
			conn.Close()
		}
		<-c.sem
		return
	}
	c.mu.Lock()
	c.idle = append(c.idle, conn)
	c.mu.Unlock()
	<-c.sem
}

// mapConnErr classifies a connection-level failure: temporary infrastructure
// problems must fail closed with ErrUnavailable, not leak as other errors.
func mapConnErr(err error) error {
	if err == nil {
		return nil
	}
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		switch lerr.ResultCode {
		case ldap.ErrorNetwork, ldap.LDAPResultServerDown, ldap.LDAPResultUnavailable, ldap.LDAPResultTimeout:
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		case ldap.LDAPResultInvalidCredentials:
			return ErrInvalidCredentials
		}
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

// normalizeLogin accepts the login forms used in the enterprise: short
// name ("doav"), "DOMAIN\\doav", UPN "doav@unicont.spb" (searched by
// userPrincipalName when LDAP_UPN_SUFFIX matches) and foreign-domain mail
// ("doav@unicont.com" -> short name). The returned attribute/value pair is
// interpolated ONLY through the escaped filter placeholder (S-01).
func (c *Client) normalizeLogin(input string) (attr, value string) {
	s := strings.TrimSpace(input)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		s = s[i+1:] // DOMAIN\user -> user
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		if c.cfg.UPNSuffix != "" && strings.EqualFold(s[i+1:], c.cfg.UPNSuffix) {
			return "userPrincipalName", s // full UPN of our domain
		}
		s = s[:i] // foreign mail domain (user@unicont.com) -> short name
	}
	return c.cfg.UserAttr, s
}

// bindName converts the normalized login into the string handed to AD as
// the bind identity in self-bind mode. AD accepts NT4 names ("unicont\doav")
// and UPNs ("doav@unicont.spb"); a bare sAMAccountName is passed through.
func (c *Client) bindName(login string) string {
	if strings.Contains(login, "@") {
		return login // UPN already (normalizeLogin kept it)
	}
	if c.cfg.UPNSuffix != "" {
		// Verified on s0005.unicont.spb: UPN bind succeeds while
		// "DOMAIN\doav" returns invalidCredentials.
		return login + "@" + c.cfg.UPNSuffix
	}
	if c.cfg.NetBIOSDomain != "" {
		return c.cfg.NetBIOSDomain + "\\" + login
	}
	return login
}

// Authenticate verifies username/password against the directory and returns
// the user with mapped roles.
//
// Service-account mode (LDAP_BIND_DN set): search as the service account,
// then verify the password with a dedicated bind AS the user. Unknown user
// triggers a dummy bind first (S-08 timing alignment).
//
// Self-bind mode (no service account): the password check IS the first
// operation — bind AS "DOMAIN\user" / UPN on a fresh TLS connection — so
// unknown-user and wrong-password naturally cost the same single failed
// bind (S-08). On success the same connection searches the user's own
// attributes (AD permits self-read of displayName/mail/memberOf).
//
// Error paths: wrong password / no such user -> ErrInvalidCredentials
// (identical upstream, S-08); infra failure -> ErrUnavailable (503, S-07).
func (c *Client) Authenticate(username, password string) (*User, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	attr, login := c.normalizeLogin(username)

	if c.cfg.SelfBind {
		return c.authenticateSelfBind(attr, login, password)
	}
	return c.authenticateServiceBind(attr, login, password)
}

// authenticateServiceBind is the classic flow with a read-only service
// account (S-03): search first, then user bind, then map roles.
func (c *Client) authenticateServiceBind(attr, login, password string) (*User, error) {
	// 1. Search by the configured login attribute, value escaped (S-01).
	conn, err := c.acquire()
	if err != nil {
		return nil, mapConnErr(err)
	}
	filter := c.userFilter(attr, login)
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter,
		[]string{"dn", c.cfg.UserAttr, c.cfg.NameAttr, c.cfg.MailAttr, "memberOf"},
		nil,
	)
	res, err := conn.Search(req)
	broken := err != nil && isConnBroken(err)
	c.release(conn, broken)
	if err != nil {
		return nil, mapConnErr(err)
	}
	switch len(res.Entries) {
	case 0:
		// S-08: perform a bind of the same shape against a dummy DN so the
		// unknown-user path costs the same LDAP work as wrong-password.
		c.dummyBind(password)
		return nil, ErrInvalidCredentials
	case 1:
		// ok
	default:
		// Duplicate matches mean a broken directory — fail closed.
		return nil, ErrAmbiguousUser
	}
	entry := res.Entries[0]

	// 2. Verify the password with a dedicated bind AS the user. The user
	// password is used for nothing else (never stored, never logged, S-09).
	if err := c.userBind(entry.DN, password); err != nil {
		return nil, err
	}

	return c.toUser(entry)
}

// authenticateSelfBind verifies the password by binding AS the user, then
// reads own attributes on the same connection (no service account needed).
func (c *Client) authenticateSelfBind(attr, login, password string) (*User, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, mapConnErr(err)
	}
	defer conn.Close()

	if err := conn.Bind(c.bindName(login), password); err != nil {
		// Unknown user and wrong password are the same single failed bind —
		// both map to the identical upstream 401 (S-08).
		if mapped := mapConnErr(err); errors.Is(mapped, ErrUnavailable) {
			return nil, mapped
		}
		return nil, ErrInvalidCredentials
	}

	// Bound as the user: read own attributes. Escaped filter (S-01).
	filter := c.userFilter(attr, login)
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter,
		[]string{"dn", c.cfg.UserAttr, c.cfg.NameAttr, c.cfg.MailAttr, "memberOf"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, mapConnErr(err)
	}
	if len(res.Entries) != 1 {
		// Bound fine but the entry is not findable/readable — fail closed
		// without revealing which half failed.
		return nil, ErrInvalidCredentials
	}
	return c.toUser(res.Entries[0])
}

// toUser maps an LDAP entry into the domain User with roles (S-12).
func (c *Client) toUser(entry *ldap.Entry) (*User, error) {
	user := &User{
		DN:          entry.DN,
		Username:    firstAttr(entry, c.cfg.UserAttr),
		DisplayName: firstAttr(entry, c.cfg.NameAttr),
		Email:       firstAttr(entry, c.cfg.MailAttr),
		MemberOf:    entry.GetAttributeValues("memberOf"),
	}
	if user.Username == "" {
		// if the login attribute is missing on the entry, fail closed.
		return nil, ErrAmbiguousUser
	}
	user.Roles = mapRoles(user.MemberOf, c.cfg.AdminGroupDN)
	return user, nil
}

// SelfBindMode reports whether the client operates without a service
// account; the auth service skips refresh-time LDAP re-reads in that mode.
func (c *Client) SelfBindMode() bool { return c.cfg.SelfBind }

// userBind opens a fresh connection and binds as the user.
func (c *Client) userBind(dn, password string) error {
	conn, err := c.dial()
	if err != nil {
		return mapConnErr(err)
	}
	defer conn.Close()
	if err := conn.Bind(dn, password); err != nil {
		// Invalid credentials (49) and unwilling-to-perform (53, e.g. locked
		// or disabled account) are both reported as plain invalid creds, so
		// account state is not leaked (S-08/S-15).
		if mapped := mapConnErr(err); errors.Is(mapped, ErrUnavailable) {
			return mapped
		}
		return ErrInvalidCredentials
	}
	return nil
}

// dummyBind burns one bind attempt against a fixed DN. Errors are ignored
// by design: the expected outcome is a failed bind (S-08).
func (c *Client) dummyBind(password string) {
	conn, err := c.dial()
	if err != nil {
		return
	}
	_ = conn.Bind(dummyBindDN, password) // expected to fail
	conn.Close()
}

// UserByDN reads a user entry by DN. Used on refresh to re-check role
// membership (S-12) without a password bind.
func (c *Client) UserByDN(dn string) (*User, error) {
	if c.cfg.SelfBind {
		// No service identity: role re-read at refresh is unavailable;
		// the auth service must use roles stored in the session instead.
		return nil, ErrUnavailable
	}
	if dn == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := c.acquire()
	if err != nil {
		return nil, mapConnErr(err)
	}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"dn", c.cfg.UserAttr, c.cfg.NameAttr, c.cfg.MailAttr, "memberOf"}, nil)
	res, err := conn.Search(req)
	broken := err != nil && isConnBroken(err)
	c.release(conn, broken)
	if err != nil {
		return nil, mapConnErr(err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	entry := res.Entries[0]
	u := &User{
		DN:          entry.DN,
		Username:    firstAttr(entry, c.cfg.UserAttr),
		DisplayName: firstAttr(entry, c.cfg.NameAttr),
		Email:       firstAttr(entry, c.cfg.MailAttr),
		MemberOf:    entry.GetAttributeValues("memberOf"),
	}
	if u.Username == "" {
		return nil, ErrInvalidCredentials
	}
	u.Roles = mapRoles(u.MemberOf, c.cfg.AdminGroupDN)
	return u, nil
}

// Ping performs a cheap directory availability check; used by /ready (S-07).
// Self-bind mode has no service credentials: a successful TLS handshake is
// the strongest check available without user credentials.
func (c *Client) Ping() error {
	if c.cfg.SelfBind {
		conn, err := c.dial()
		if err != nil {
			return mapConnErr(err)
		}
		conn.Close()
		return nil
	}
	conn, err := c.acquire()
	if err != nil {
		return mapConnErr(err)
	}
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"dn"}, nil)
	_, err = conn.Search(req)
	broken := err != nil && isConnBroken(err)
	c.release(conn, broken)
	return mapConnErr(err)
}

// Close drains the pool.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.idle {
		conn.Close()
	}
	c.idle = nil
}

// isConnBroken reports whether the connection cannot be reused.
func isConnBroken(err error) bool {
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		switch lerr.ResultCode {
		case ldap.ErrorNetwork, ldap.LDAPResultServerDown, ldap.LDAPResultUnavailable, ldap.LDAPResultTimeout:
			return true
		}
		return false
	}
	return true // unexpected non-LDAP errors are treated as transport breakage
}

func firstAttr(e *ldap.Entry, name string) string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

// mapRoles converts AD group membership into APS roles. Exact membership of
// LDAP_ADMIN_GROUP_DN (case-insensitive) grants "admin" (S-12). The role is
// frozen into the access token; revocation takes effect within access TTL.
func mapRoles(memberOf []string, adminGroupDN string) []string {
	roles := []string{}
	if adminGroupDN == "" {
		return roles
	}
	for _, dn := range memberOf {
		if strings.EqualFold(strings.TrimSpace(dn), strings.TrimSpace(adminGroupDN)) {
			roles = append(roles, "admin")
			break
		}
	}
	return roles
}
