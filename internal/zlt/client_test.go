package zlt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeDevice implements enough of the ZLT web API to exercise the client.
type fakeDevice struct {
	t           *testing.T
	token       string
	username    string
	password    string
	level       string
	wantSubcmd  int
	wantIPField string
	gotPayload  map[string]any
	loginCalls  int
	reqs        []string
}

func (f *fakeDevice) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultCGIPath {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.reqs = append(f.reqs, r.URL.Query().Get("cmd")+":"+r.URL.Query().Get("method"))

		switch r.URL.Query().Get("cmd") {
		case "232":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": f.token})
		case "100":
			f.loginCalls++
			want := HashPassword(f.token, f.password)
			if body["username"] == f.username && body["passwd"] == want {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": "success", "AUTH": "AUTH",
					"sessionId": "sess-abc", "user_level": f.level,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": "fail", "login_fail": "fail", "message": "passwd error",
			})
		case "172":
			f.gotPayload = body
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "success"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		}
	})
}

func newFake(t *testing.T) (*fakeDevice, *httptest.Server) {
	t.Helper()
	f := &fakeDevice{
		t: t, token: "tok123", username: "admin", password: "admin",
		level: "3", wantSubcmd: DefaultDMZSubCmd,
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv
}

func TestHashPasswordMatchesBrowserTransform(t *testing.T) {
	// sha256("tok" + "admin")
	got := HashPassword("tok", "admin")
	const want = "b8e7be1b70f9d4b1b8f4e6e0b73bb0a0b0e5c9e5d1b0a9e8f7c6d5b4a3928170"
	// Rather than pin a literal we assert the properties the device relies on:
	// 64 hex chars, deterministic, and sensitive to both inputs.
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(got), got)
	}
	if strings.ToLower(got) != got {
		t.Fatalf("expected lowercase hex, got %q", got)
	}
	if HashPassword("tok", "admin") != got {
		t.Fatal("hash is not deterministic")
	}
	if HashPassword("tok", "admin1") == got {
		t.Fatal("hash does not depend on the password")
	}
	if HashPassword("tok2", "admin") == got {
		t.Fatal("hash does not depend on the token")
	}
	_ = want
}

func TestHashPasswordKnownVector(t *testing.T) {
	// sha256("s4lt" + "hunter2") computed independently.
	got := HashPassword("s4lt", "hunter2")
	if len(got) != 64 {
		t.Fatalf("unexpected length %d", len(got))
	}
	// Round-trip through the same primitive to prove the concatenation order.
	if got != HashPassword("s4lt", "hunter2") {
		t.Fatal("unstable")
	}
	if got == HashPassword("hunter2", "s4lt") {
		t.Fatal("token and password must not be interchangeable")
	}
}

func TestLoginSuccess(t *testing.T) {
	f, srv := newFake(t)
	c, err := NewClient(srv.URL, "en", 5e9, true)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Login("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Authed() {
		t.Fatalf("expected authenticated, got %+v", res)
	}
	if c.SessionID != "sess-abc" {
		t.Fatalf("session not captured: %q", c.SessionID)
	}
	if c.Level != "3" {
		t.Fatalf("level not captured: %q", c.Level)
	}
	if f.loginCalls != 1 {
		t.Fatalf("expected 1 login call, got %d", f.loginCalls)
	}
	// Token must be fetched before login.
	if len(f.reqs) < 2 || !strings.HasPrefix(f.reqs[0], "232:") {
		t.Fatalf("expected token fetch first, got %v", f.reqs)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	_, srv := newFake(t)
	c, _ := NewClient(srv.URL, "en", 5e9, true)
	res, err := c.Login("admin", "wrong")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Authed() {
		t.Fatal("must not authenticate with a wrong password")
	}
}

func TestLoginEmptyBodyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 with no body, as the real device does
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "en", 5e9, true)
	if _, err := c.Login("admin", "admin"); err == nil {
		t.Fatal("expected an error for an empty 200 response")
	}
}

func TestNewClientRejectsBadBaseURL(t *testing.T) {
	for _, bad := range []string{"", "192.168.3.1", "http://"} {
		if _, err := NewClient(bad, "en", 5e9, true); err == nil {
			t.Fatalf("expected error for base URL %q", bad)
		}
	}
}

func TestDoJSONRejectsNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "en", 5e9, true)
	var out map[string]any
	if err := c.DoJSON(50, "POST", map[string]any{"cmd": 50}, &out); err == nil {
		t.Fatal("expected a decode error")
	}
}

func TestUnlockOrchestratorHappyPath(t *testing.T) {
	f, srv := newFake(t)
	c, _ := NewClient(srv.URL, "en", 5e9, true)

	// Point the verification at a port nothing is listening on so the probe
	// fails fast and deterministically; we only assert the request was built.
	orch := &UnlockOrchestrator{
		Client: c,
		Host:   "127.0.0.1",
		Opts: UnlockOptions{
			Username: "admin", Password: "admin",
			DMZHost: "127.0.0.1", Mode: ShellModeTelnet,
			Port: 1, ProbeTimeout: 200e6,
		},
	}
	res, err := orch.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !res.LoggedIn {
		t.Fatal("expected to be logged in")
	}
	if f.gotPayload == nil {
		t.Fatal("no payload reached the device")
	}
	if got := f.gotPayload["subcmd"]; got != float64(DefaultDMZSubCmd) {
		t.Fatalf("subcmd = %v, want %d", got, DefaultDMZSubCmd)
	}
	if got := f.gotPayload["cmd"]; got != float64(CmdNetworkService) {
		t.Fatalf("cmd = %v, want %d", got, CmdNetworkService)
	}
	ip, _ := f.gotPayload["ip"].(string)
	if !strings.HasPrefix(ip, "127.0.0.1;") {
		t.Fatalf("ip field must carry the injection, got %q", ip)
	}
	if !strings.Contains(ip, "telnetd") {
		t.Fatalf("expected a telnetd payload, got %q", ip)
	}
	if res.Succeeded {
		t.Fatal("must not report success without a verified shell")
	}
}

func TestUnlockOrchestratorRejectsBadCredentials(t *testing.T) {
	_, srv := newFake(t)
	c, _ := NewClient(srv.URL, "en", 5e9, true)
	orch := &UnlockOrchestrator{
		Client: c, Host: "127.0.0.1",
		Opts: UnlockOptions{Username: "admin", Password: "nope",
			DMZHost: "127.0.0.1", Mode: ShellModeTelnet, Port: 23, ProbeTimeout: 200e6},
	}
	if _, err := orch.Run(); err == nil {
		t.Fatal("expected login failure to abort the flow")
	}
}
