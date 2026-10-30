// Package zlt provides a small, dependency-free client for the ZLT X16
// (SDX65 / SIMCom SIM8260E) web management API, plus the provisioning
// primitives used to enable a root shell on devices an operator controls.
//
// The protocol was reverse engineered from the device's own served JavaScript
// (/tzwww/js/login.js and /tzwww/js/main.js). See docs/protocol.md.
package zlt

import (
	"encoding/json"
	"strings"
)

// RequestCmd values taken from the RequestCmd enum in the device's main.js.
const (
	CmdSYSInfo          = 0
	CmdNetConnect       = 48
	CmdNetDisconnect    = 49
	CmdGetHTML          = 50
	CmdInitPage         = 80
	CmdReboot           = 99
	CmdLogin            = 100
	CmdLogout           = 101
	CmdChangePasswd     = 102
	CmdApplyFilter      = 20
	CmdNetworkService   = 172
	CmdGetNextLoginTime = 232
	CmdDeviceInfo       = 207
	CmdWanInfo          = 206
)

// Default DMZ/network-service sub-command. The device's saved request artifact
// (/productinfo/tzcfg/iptables/iptables_dmz_function) records cmd=172 subcmd=6.
const DefaultDMZSubCmd = 6

// LoginResult is what the device returns for cmd=100.
type LoginResult struct {
	Success    Flag   `json:"success"`
	Message    string `json:"message"`
	SessionID  string `json:"sessionId"`
	Auth       Flag   `json:"AUTH"`
	UserLevel  string `json:"user_level"`
	AccountLvl string `json:"account_level"`
	LoginFail  Flag   `json:"login_fail"`
	LoginFail2 Flag   `json:"login_fail2"`
	LoginTimes string `json:"login_times"`
}

// Authed reports whether the device accepted the credentials.
func (l LoginResult) Authed() bool {
	return l.Auth.Truthy() || strings.EqualFold(string(l.Success), "success") || l.SessionID != ""
}

// RateLimited reports whether the failure was a lockout rather than a bad
// password. Both are "login_fail", but only the lockout is worth waiting out.
func (l LoginResult) RateLimited() bool {
	return l.LoginFail2.Truthy() || l.LoginTimes != ""
}

// Flag is a JSON value that the device sends either as a boolean or as a
// string, depending on the command. `success` and friends are the worst
// offenders: cmd=100 answers "success":"success" while cmd=232 answers
// "success":true. Decoding into a plain bool or string fails on the other form.
type Flag string

// UnmarshalJSON accepts true/false, "true"/"false", numbers and strings.
func (f *Flag) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		*f = ""
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		*f = Flag(str)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(b, &num); err == nil {
		*f = Flag(num.String())
		return nil
	}
	var boolean bool
	if err := json.Unmarshal(b, &boolean); err != nil {
		return err
	}
	if boolean {
		*f = "true"
	} else {
		*f = "false"
	}
	return nil
}

// Truthy reports whether the value means "yes".
func (f Flag) Truthy() bool {
	switch strings.ToLower(string(f)) {
	case "1", "true", "yes", "ok", "success", "auth":
		return true
	}
	return false
}

func (f Flag) String() string { return string(f) }

// TokenResult is the cmd=232 response. The token salts the password hash.
//
// A unit in login lockout returns buffer:"2" plus netx_login_time (seconds until
// the next attempt is allowed); both are surfaced so callers can say so instead
// of reporting a wrong password.
type TokenResult struct {
	Token         string `json:"token"`
	Success       Flag   `json:"success"`
	Message       string `json:"message"`
	Buffer        Flag   `json:"buffer"`
	NextLoginTime string `json:"netx_login_time"`
}

// LockedOut reports whether the device is refusing logins for a while.
func (t TokenResult) LockedOut() bool { return t.Buffer == "2" }

// GenericResponse covers the simple ack shape most config commands return.
type GenericResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Options are the common request parameters.
type Options struct {
	// BaseURL is the device origin, e.g. "http://192.168.3.1". Required.
	BaseURL string
	// Language query parameter; the UI sends "en" or "cn".
	Language string
	// Timeout in seconds for HTTP requests.
	TimeoutSeconds int
	// InsecureTLS allows self-signed certs when talking to https.
	InsecureTLS bool
}
