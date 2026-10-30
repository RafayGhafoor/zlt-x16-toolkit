package zlt

import (
	"fmt"
	"strings"
)

// The privilege tier, and why AT/SMS "become available"
// ======================================================
//
// The account tier is a single GLOBAL runtime flag, not a property of a session:
//
//	mdlcfg -o account_level     # 1 = super, 2 = senior, 3 = ordinary web user
//
// `authority_checkt(cmd)` in the vendor CGI consults USR_WEB_PAGE_HIDE (a fixed
// bitmap that ships in the firmware) together with `account_level` to decide
// whether a command is allowed. Restricted commands answer
// {"success":false,"message":"LIMITED_ACCESS"} when the flag says 3.
//
// Measured on X16-OMN247, same session, nothing else changed:
//
//	mdlcfg -f account_level=1 ; cmd=270 SEND_AT  -> {"success":true} + the IMEI
//	mdlcfg -f account_level=3 ; cmd=270 SEND_AT  -> {"success":false,"message":"LIMITED_ACCESS"}
//
// Two consequences that are easy to get wrong:
//
//  1. Logging in RESETS the flag to that account's tier. admin/admin logs in at
//     level 3, so any earlier elevation is undone by the next login.
//  2. Because it is global rather than per-session, every request is judged
//     against whatever the flag says at that instant - which is exactly how a
//     front shim can elevate all of them.
//
// That is what happened on this unit: /tzwww/cgi-bin/http.cgi is a small static
// shim that runs `mdlcfg -f account_level=1` (and writes /tmp/account_level)
// before exec'ing the real vendor CGI, which was kept beside it as
// http.cgi.bak. The privilege that "appears" is that shim - not anything the
// firmware shipped. The bitmap itself is factory: USR_WEB_PAGE_HIDE matches the
// shipped value and /productinfo/tzcfg/main_config still carries its 1980 mtime.
//
// SMS is unrelated: it is gated by the plain config switch SYS_SMS_SW (=1 on
// this SKU) and cmd=12 SMS_INFO succeeds even at level 3.

// Account levels, as the device names them.
const (
	LevelSuper   = 1
	LevelSenior  = 2
	LevelUser    = 3
	LevelUnknown = 0
)

// LevelNames describes each tier in the device's own vocabulary.
var LevelNames = map[int]string{
	LevelSuper:  "super (highest) - restricted commands allowed",
	LevelSenior: "senior",
	LevelUser:   "ordinary web user - restricted commands answer LIMITED_ACCESS",
}

// Level describes the live tier and the two things that decide it.
type Level struct {
	Current int
	Raw     string
	// ShimDetected is true when the CGI entry point is not the vendor binary but
	// a shim that forces the level before handing off.
	ShimDetected bool
	ShimNote     string
	// CGIPath / CGIInfo describe what is actually being executed.
	CGIPath  string
	CGIBytes string
	// Backups are other executables in cgi-bin/ (mini_httpd runs cgi-bin/* as
	// root, so a leftover .bak is itself reachable by URL).
	Backups []string
}

// String renders a one-block summary.
func (l Level) String() string {
	var b strings.Builder
	name := LevelNames[l.Current]
	if name == "" {
		name = "unknown"
	}
	fmt.Fprintf(&b, "account_level   %d  (%s)\n", l.Current, name)
	fmt.Fprintf(&b, "cgi             %s  %s\n", l.CGIPath, l.CGIBytes)
	if l.ShimDetected {
		fmt.Fprintf(&b, "shim            YES - %s\n", l.ShimNote)
	} else {
		b.WriteString("shim            no - stock vendor CGI\n")
	}
	for _, e := range l.Backups {
		fmt.Fprintf(&b, "also present    %s\n", e)
	}
	return b.String()
}

// LevelReader inspects and changes the tier over the injected root shell.
type LevelReader struct {
	Shell *Shell
}

// Read reports the current tier and what is serving the web UI.
func (r *LevelReader) Read() (Level, error) {
	l := Level{Current: LevelUnknown}

	out, _, err := r.Shell.Run("mdlcfg -o account_level")
	if err != nil {
		return l, err
	}
	l.Raw = strings.TrimSpace(out)
	fmt.Sscanf(l.Raw, "%d", &l.Current)

	// The URL path is /cgi-bin/...; the docroot on the device is /tzwww.
	l.CGIPath = DefaultCGIPath
	fsPath := "/tzwww" + DefaultCGIPath
	if b, _, err := r.Shell.Run("wc -c < " + fsPath + " 2>/dev/null"); err == nil {
		l.CGIBytes = strings.TrimSpace(b) + " bytes"
	}

	// The shim is recognisable by its own strings: a stock CGI never calls mdlcfg.
	if out, _, err := r.Shell.Run(
		"grep -c 'mdlcfg -f account_level=1' " + fsPath + " 2>/dev/null"); err == nil {
		n := strings.TrimSpace(out)
		if n != "" && n != "0" {
			l.ShimDetected = true
			l.ShimNote = "the entry point forces account_level=1 before exec'ing the real CGI"
		}
	}

	// printf, not ls: busybox ls emits colour escapes.
	if out, _, err := r.Shell.Run("printf '%s\\n' /tzwww/cgi-bin/*"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(stripANSI(line))
			if line == "" || strings.HasSuffix(line, "/http.cgi") {
				continue
			}
			l.Backups = append(l.Backups, line+"   (mini_httpd runs cgi-bin/* as root, so this is URL-reachable)")
		}
	}
	return l, nil
}

// Set writes the tier. It does NOT survive a login: the CGI resets the flag to
// the authenticated account's tier, so set it immediately before the request you
// want elevated, or install the front shim.
func (r *LevelReader) Set(level int) error {
	if level < LevelSuper || level > LevelUser {
		return fmt.Errorf("zlt: level must be 1, 2 or 3")
	}
	out, code, err := r.Shell.Run(fmt.Sprintf("mdlcfg -f account_level=%d", level))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("zlt: mdlcfg failed (exit %d): %s", code, strings.TrimSpace(out))
	}
	// Read back rather than trust the exit code.
	got, _, err := r.Shell.Run("mdlcfg -o account_level")
	if err != nil {
		return err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(got), "%d", &n); err != nil {
		return fmt.Errorf("zlt: could not read back the level (%q)", strings.TrimSpace(got))
	}
	if n != level {
		return fmt.Errorf("zlt: level did not stick (wanted %d, device says %d)", level, n)
	}
	return nil
}

// stripANSI removes terminal colour sequences.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// LevelUnlocks lists what the tier is observed to gate on this firmware.
func LevelUnlocks() string {
	return strings.TrimSpace(`
level 3 (admin/admin logs in here)   restricted commands answer LIMITED_ACCESS
                                        - cmd=270 SEND_AT  (the web AT console)
                                        - and the super-only menu pages stay hidden
level 1                                 those commands succeed
                                        - verified: cmd=270 returns the IMEI
Not gated by level: cmd=172 subcmd=6 (the DMZ injection), cmd=12 SMS_INFO, cmd=80/100.
`)
}
