package zlt

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ShellState describes what, if anything, is answering on a port.
type ShellState struct {
	Port     int
	Open     bool
	Banner   string
	NoAuth   bool
	Duration time.Duration
	Err      error
}

// String renders a one-line summary.
func (s ShellState) String() string {
	switch {
	case !s.Open:
		return fmt.Sprintf("port %d: closed", s.Port)
	case s.Err != nil:
		return fmt.Sprintf("port %d: open (no data: %v)", s.Port, s.Err)
	case s.NoAuth:
		return fmt.Sprintf("port %d: open, NO AUTH (banner=%q)", s.Port, strings.TrimSpace(s.Banner))
	default:
		return fmt.Sprintf("port %d: open (banner=%q)", s.Port, strings.TrimSpace(s.Banner))
	}
}

// ProbeShell connects to host:port and decides whether an unauthenticated shell
// is available.
//
// Heuristic: a ZLT telnetd started with "-l /bin/sh" either emits no login
// prompt at all and answers with a shell banner / prompt, or emits only telnet
// IAC negotiation. A vendor telnetd with a real login handler sends a
// "login:"-style prompt, which we treat as NOT unauth.
func ProbeShell(host string, port int, timeout time.Duration) ShellState {
	st := ShellState{Port: port}
	addr := net.JoinHostPort(host, fmt.Sprint(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	st.Duration = time.Since(start)
	if err != nil {
		st.Err = err
		return st
	}
	defer conn.Close()
	st.Open = true

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		// Open but silent is the normal shape for busybox telnetd + /bin/sh
		// before any IAC negotiation is answered.
		st.Err = err
		st.NoAuth = true
		return st
	}
	st.Banner = string(buf[:n])
	st.NoAuth = looksUnauthenticated(st.Banner)
	return st
}

// looksUnauthenticated decides from a banner whether a login handler is present.
func looksUnauthenticated(banner string) bool {
	low := strings.ToLower(banner)
	// Strip telnet IAC negotiation bytes so they don't confuse matching.
	cleaned := strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, low)

	for _, need := range []string{"login:", "username:", "password:"} {
		if strings.Contains(cleaned, need) {
			return false
		}
	}
	// A bare shell prompt is the strongest signal.
	if strings.Contains(cleaned, "/ #") || strings.Contains(cleaned, "# ") || strings.Contains(cleaned, "$ ") {
		return true
	}
	// No prompt at all but the socket is talking: still no auth handler seen.
	return true
}

// PortOpen is a plain TCP reachability check.
func PortOpen(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
