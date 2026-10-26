package zlt

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeTelnet binds a local listener that speaks a fixed greeting.
func fakeTelnet(t *testing.T, greeting string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if greeting != "" {
				_, _ = c.Write([]byte(greeting))
			}
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return p
}

func TestProbeShellDetectsShellPrompt(t *testing.T) {
	port := fakeTelnet(t, "\r\n/ # ")
	st := ProbeShell("127.0.0.1", port, 2*time.Second)
	if !st.Open {
		t.Fatal("expected the port to be open")
	}
	if !st.NoAuth {
		t.Fatalf("a bare shell prompt means no auth: %+v", st)
	}
}

func TestProbeShellTreatsLoginPromptAsAuthenticated(t *testing.T) {
	for _, greet := range []string{
		"\r\nlogin: ",
		"\r\nUsername: ",
		"\r\nPassword: ",
	} {
		port := fakeTelnet(t, greet)
		st := ProbeShell("127.0.0.1", port, 2*time.Second)
		if st.NoAuth {
			t.Fatalf("greeting %q has a login handler, must not be flagged as no-auth", greet)
		}
	}
}

func TestProbeShellSilentIsNoAuth(t *testing.T) {
	// busybox telnetd with -l /bin/sh often says nothing until IAC is answered.
	port := fakeTelnet(t, "")
	st := ProbeShell("127.0.0.1", port, 500*time.Millisecond)
	if !st.Open {
		t.Fatal("expected open")
	}
	if !st.NoAuth {
		t.Fatal("a silent listener should be treated as no-auth")
	}
}

func TestProbeShellClosedPort(t *testing.T) {
	// Grab a port then close it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	st := ProbeShell("127.0.0.1", p, 300*time.Millisecond)
	if st.Open {
		t.Fatalf("expected closed, got %+v", st)
	}
	if st.NoAuth {
		t.Fatal("a closed port must never be reported as no-auth")
	}
}

func TestLooksUnauthenticatedIgnoresIACBytes(t *testing.T) {
	// Real busybox telnetd sends IAC DO/WILL negotiation first.
	banner := "\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\n/ # "
	if !looksUnauthenticated(banner) {
		t.Fatal("IAC negotiation must not hide a shell prompt")
	}
}

func TestLooksUnauthenticatedFindsLoginBehindNoise(t *testing.T) {
	banner := "\xff\xfd\x18\xff\xfd\x20\r\nUbuntu 22.04\r\nlogin: "
	if looksUnauthenticated(banner) {
		t.Fatal("must detect the login prompt through the noise")
	}
}

func TestShellStateString(t *testing.T) {
	if got := (ShellState{Port: 23}).String(); !strings.Contains(got, "closed") {
		t.Fatalf("got %q", got)
	}
	if got := (ShellState{Port: 23, Open: true, NoAuth: true, Banner: "/ #"}).String(); !strings.Contains(got, "NO AUTH") {
		t.Fatalf("got %q", got)
	}
}

func TestPortOpen(t *testing.T) {
	port := fakeTelnet(t, "")
	if !PortOpen("127.0.0.1", port, time.Second) {
		t.Fatal("expected open")
	}
	if PortOpen("127.0.0.1", 1, 200*time.Millisecond) {
		t.Fatal("port 1 should not be open")
	}
}

func TestVerifyOnlyProbesEachPort(t *testing.T) {
	open := fakeTelnet(t, "/ # ")
	states := VerifyOnly("127.0.0.1", []int{open, 1}, 400*time.Millisecond)
	if len(states) != 2 {
		t.Fatalf("expected 2 states, got %d", len(states))
	}
	if !states[0].Open || !states[0].NoAuth {
		t.Fatalf("first port should be an open no-auth shell: %+v", states[0])
	}
	if states[1].Open || states[1].NoAuth {
		t.Fatalf("second port should be closed: %+v", states[1])
	}
	if states[0].Port != open {
		t.Fatalf("port mismatch: got %d want %d", states[0].Port, open)
	}
}
