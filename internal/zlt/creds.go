package zlt

import (
	"fmt"
	"os"
	"strings"
)

// Why this file exists
// --------------------
// The 172/6 DMZ handler is gated on *session validity only*. The firmware's
// own authorisation routine (http.c "authenticate") is a per-command switch
// whose only outcomes are "session valid" and NO_AUTH - it never compares the
// account tier. process_network_service() contains no level check either.
//
// So the shipped `admin` account (level "3", the lowest) is enough to reach the
// root shell. The `superadmin` credential is NOT a prerequisite; it is only
// useful for the UI pages that are hidden below level 1.
//
// Verified on X16-OMN247 against the *stock* vendor CGI with account_level=3
// forced: an admin/admin session executed `id > /tmp/...` as uid=0.
//
// The chain below therefore starts at the least surprising credential and falls
// back only if the device rejects it (e.g. the admin password was changed).

// Credential is one login attempt in the fallback chain.
type Credential struct {
	User string
	Pass string
	// Note explains what this account is, for user-facing output.
	Note string
}

func (c Credential) String() string { return c.User + "/" + redact(c.Pass) }

// redact keeps a credential printable without dumping the password in full.
func redact(s string) string {
	if len(s) <= 2 {
		return strings.Repeat("*", len(s))
	}
	return s[:1] + strings.Repeat("*", len(s)-1)
}

// SuperPasswordEnv names the environment variable that may carry the per-device
// super-account password.
//
// The super password is deliberately NOT compiled into this tool. The device repo
// treats it as per-device (see docs/protocol.md), and it is not needed anyway: the
// DMZ handler is gated on session validity, not on account tier, so the ordinary
// admin account reaches it. Set SUPER_PWD only if the admin password has been
// changed and you want the chain to try the super account.
const SuperPasswordEnv = "SUPER_PWD"

// ShippedCredentials returns the credential chain in the order it should be tried.
// Published defaults for this model only; no live password is embedded.
//
// The first entry is the ordinary web user. It is enough for `unlock`.
func ShippedCredentials() []Credential {
	out := []Credential{
		{User: DefaultUser, Pass: DefaultPass, Note: "shipped web user (level 3) - sufficient for unlock"},
	}
	if seniorUserName != "" {
		out = append(out, Credential{
			User: seniorUserName,
			Pass: seniorPass,
			Note: "shipped senior account (level 2)",
		})
	}
	// Only offered when the operator supplies it, because it is per-device.
	if superUserName != "" {
		if pw := os.Getenv(SuperPasswordEnv); pw != "" {
			out = append(out, Credential{
				User: superUserName,
				Pass: pw,
				Note: "super account from $" + SuperPasswordEnv + " (level 1) - only needed for hidden UI pages",
			})
		}
	}
	return out
}

// LoginOutcome records one attempted credential.
type LoginOutcome struct {
	Credential
	OK      bool
	Level   string
	Message string
}

// LoginChain tries each credential in order and returns the first session that
// the device accepts. It returns every attempt so callers can report why the
// earlier ones failed.
//
// The Client is left holding the winning session id and level.
func (c *Client) LoginChain(creds []Credential) (LoginOutcome, []LoginOutcome, error) {
	var attempts []LoginOutcome
	for _, cr := range creds {
		res, err := c.Login(cr.User, cr.Pass)
		if err == nil && res.Authed() {
			name := cr.Note
			if name == "" {
				name = cr.String()
			}
			_ = name
			attempts = append(attempts, LoginOutcome{
				Credential: cr,
				OK:         true,
				Level:      c.Level,
			})
			return attempts[len(attempts)-1], attempts, nil
		}
		msg := res.Message
		if msg == "" && err != nil {
			msg = err.Error()
		}
		if msg == "" {
			msg = "rejected"
		}
		attempts = append(attempts, LoginOutcome{
			Credential: cr,
			OK:         false,
			Message:    msg,
		})
	}
	return LoginOutcome{}, attempts, fmt.Errorf("zlt: no shipped credential was accepted (%d tried)", len(creds))
}

// LevelIsSuper reports whether the device's reported tier is the top one.
// Purely informational: unlock does not depend on it.
func LevelIsSuper(level string) bool { return level == "1" }
