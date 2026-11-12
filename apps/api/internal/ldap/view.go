package ldap

// SettingsView is the admin-safe projection of the effective LDAP settings:
// no secrets, booleans/mode resolved for display.
type SettingsView struct {
	Mode          string `json:"mode"` // service-bind | self-bind
	URL           string `json:"url"`
	StartTLS      bool   `json:"start_tls"`
	TLSInsecure   bool   `json:"tls_insecure"`
	CAFile        string `json:"ca_file,omitempty"`
	BindDN        string `json:"bind_dn,omitempty"` // empty in self-bind mode
	BaseDN        string `json:"base_dn"`
	ObjectClass   string `json:"object_class"`
	UserAttr      string `json:"user_attr"`
	NameAttr      string `json:"name_attr"`
	MailAttr      string `json:"mail_attr"`
	UPNSuffix     string `json:"upn_suffix,omitempty"`
	NetBIOSDomain string `json:"netbios_domain,omitempty"`
	AdminGroupDN  string `json:"admin_group_dn,omitempty"`
	PoolSize      int    `json:"pool_size"`
	Timeout       string `json:"timeout"`
	Retry         int    `json:"retry"`
}

// View renders the settings without the bind password (S-03/S-09).
func (c Settings) View() SettingsView {
	mode := "service-bind"
	if c.SelfBind {
		mode = "self-bind"
	}
	return SettingsView{
		Mode:          mode,
		URL:           c.URL,
		StartTLS:      c.StartTLS,
		TLSInsecure:   c.InsecureTLS,
		CAFile:        c.CAFile,
		BindDN:        c.BindDN,
		BaseDN:        c.BaseDN,
		ObjectClass:   c.ObjectClass,
		UserAttr:      c.UserAttr,
		NameAttr:      c.NameAttr,
		MailAttr:      c.MailAttr,
		UPNSuffix:     c.UPNSuffix,
		NetBIOSDomain: c.NetBIOSDomain,
		AdminGroupDN:  c.AdminGroupDN,
		PoolSize:      c.PoolSize,
		Timeout:       c.Timeout.String(),
		Retry:         c.Retry,
	}
}

// PublicUser is the formatted user info shown in the LDAP diagnostics page.
type PublicUser struct {
	DN          string   `json:"dn"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	MemberOf    []string `json:"member_of"`
	Roles       []string `json:"roles"`
}

// Public renders the diagnostic projection of an authenticated user.
func (u *User) Public() *PublicUser {
	if u == nil {
		return nil
	}
	memberOf := u.MemberOf
	if memberOf == nil {
		memberOf = []string{}
	}
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	return &PublicUser{
		DN:          u.DN,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		MemberOf:    memberOf,
		Roles:       roles,
	}
}
