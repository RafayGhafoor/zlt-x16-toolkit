// Package zlt provides a small, dependency-free client for the ZLT X16
// (SDX65 / SIMCom SIM8260E) web management API, plus the provisioning
// primitives used to enable a root shell on devices an operator controls.
//
// The protocol was reverse engineered from the device's own served JavaScript
// (/tzwww/js/login.js and /tzwww/js/main.js). See docs/protocol.md.
package zlt

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
	Success    string `json:"success"`
	Message    string `json:"message"`
	SessionID  string `json:"sessionId"`
	Auth       string `json:"AUTH"`
	UserLevel  string `json:"user_level"`
	AccountLvl string `json:"account_level"`
}

// Authed reports whether the device accepted the credentials.
func (l LoginResult) Authed() bool {
	return l.Auth == "AUTH" || l.Success == "success" || l.SessionID != ""
}

// TokenResult is the cmd=232 response. The token salts the password hash.
type TokenResult struct {
	Token   string `json:"token"`
	Success string `json:"success"`
	Message string `json:"message"`
}

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
