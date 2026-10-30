package zlt

import (
	"strings"
	"testing"
)

// The tier is what gates the restricted commands, and it was established
// by experiment on the unit:
//
//	mdlcfg -f account_level=1 ; cmd=270 -> success, IMEI returned
//	mdlcfg -f account_level=3 ; cmd=270 -> LIMITED_ACCESS
//
// Nothing here talks to a device; these pin the reporting and the guard rails.

func TestLevelNamesCoverTheThreeTiers(t *testing.T) {
	for _, l := range []int{LevelSuper, LevelSenior, LevelUser} {
		if LevelNames[l] == "" {
			t.Fatalf("level %d has no description", l)
		}
	}
	if !strings.Contains(LevelNames[LevelUser], "LIMITED_ACCESS") {
		t.Fatal("the ordinary tier should be described by its refusal, since that is what you observe")
	}
}

func TestLevelStringReportsShim(t *testing.T) {
	stock := Level{Current: LevelUser, CGIPath: "/cgi-bin/http.cgi", CGIBytes: "2188384 bytes"}
	out := stock.String()
	if !strings.Contains(out, "shim            no") {
		t.Fatalf("a stock CGI must be reported as no shim:\n%s", out)
	}

	shimmed := Level{
		Current:      LevelSuper,
		CGIPath:      "/cgi-bin/http.cgi",
		CGIBytes:     "468680 bytes",
		ShimDetected: true,
		ShimNote:     "forces account_level=1",
		Backups:      []string{"/tzwww/cgi-bin/http.cgi.bak (URL-reachable)"},
	}
	out = shimmed.String()
	if !strings.Contains(out, "shim            YES") {
		t.Fatalf("shim not reported:\n%s", out)
	}
	if !strings.Contains(out, "http.cgi.bak") {
		t.Fatalf("sibling CGI not reported:\n%s", out)
	}
}

func TestSetRejectsOutOfRange(t *testing.T) {
	r := &LevelReader{}
	for _, bad := range []int{-1, 0, 4, 99} {
		if err := r.Set(bad); err == nil {
			t.Fatalf("Set(%d) should be rejected before touching the device", bad)
		}
	}
}

// stripANSI exists because busybox ls colours its output and it ended up in the
// file list.
func TestStripANSI(t *testing.T) {
	in := "\x1b[1;32mhttp.cgi\x1b[m"
	if got := stripANSI(in); got != "http.cgi" {
		t.Fatalf("stripANSI = %q", got)
	}
	if got := stripANSI("http.cgi.bak"); got != "http.cgi.bak" {
		t.Fatalf("plain string mangled: %q", got)
	}
}

// The tier must never be presented as something unlock depends on.
func TestLevelUnlocksNamesTheUngatedCommands(t *testing.T) {
	s := LevelUnlocks()
	if !strings.Contains(s, "Not gated by level") {
		t.Fatalf("must say what the tier does NOT gate:\n%s", s)
	}
	for _, need := range []string{"cmd=270", "cmd=172", "SMS_INFO"} {
		if !strings.Contains(s, need) {
			t.Fatalf("%q missing from %q", need, s)
		}
	}
}
