package zlt

import (
	"fmt"
	"regexp"
	"strings"
)

// Talking to the modem
// --------------------
// This device has no AT character device you may open. The SIM8260E is on the
// same SDX65 die as the application CPU, there is no ttyUSB/ttyACM, and
// /bin/atcmd_daemon holds /dev/smd8 for the lifetime of the boot while reading
// indications from /dev/smd9. Opening a node behind its back interleaves with
// its multiplexer and the dialer's failure path reboots the router
// ("Dialer reboot system cause AT send failed more than %d times").
//
// The supported way in is the vendor's own serialised client:
//
//	/bin/atcmd "AT+CGSN"      ->  atcmd_receive:
//	                              861702085648268
//	                              OK
//
// It is root-only in practice (the socket pair lives in /tmp/.sockmsg with
// 0755 root-owned sockets), which is exactly what the unlock gives you. That is
// the whole reason AT/IMEI work is reachable at all - and it has nothing to do
// with /etc/shadow. Root is already root; no password is involved.

const (
	// ATCmdBin is the vendor's serialised AT client.
	ATCmdBin = "/bin/atcmd"
	// ATCmdTimeout is per-call, and MUST use SIGKILL: atcmd ignores SIGTERM and a
	// plain timeout leaves the shared channel held.
	ATCmdTimeout = 8
)

// ATResult is one command and what the modem said.
type ATResult struct {
	Cmd       string
	Payload   []string
	OK        bool
	Error     string
	Raw       string
	Forbidden bool
	Reason    string
}

// String renders the payload, one line per element.
func (r ATResult) String() string {
	if r.Forbidden {
		return fmt.Sprintf("%s  REFUSED: %s", r.Cmd, r.Reason)
	}
	out := strings.Join(r.Payload, "\n")
	if !r.OK {
		if r.Error != "" {
			out += "\nERROR: " + r.Error
		} else {
			out += "\nERROR"
		}
	}
	return out
}

// Single returns the first payload line, which is what most queries answer.
func (r ATResult) Single() string {
	if len(r.Payload) == 0 {
		return ""
	}
	return r.Payload[0]
}

// Commands that are never safe to send, whatever flags are set. Each one is a
// write to persistent modem state, or a known channel-killer.
//
// The IMEI/NV write paths are refused rather than merely flagged: they rewrite
// identity material that is (a) not ours to change and (b) illegal to alter in
// most jurisdictions, and a mistyped NV write bricks an attach. Reads are never
// blocked - use AT+CGSN / AT+SIMEI? / AT+CNVR=<n>,0.
var atForbidden = []struct {
	pat *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`^AT\+CLAC`), "never terminates on this unit and wedges atcmd_daemon for every client"},
	{regexp.MustCompile(`^AT\+CFUN\?`), "hangs the channel on this firmware"},
	{regexp.MustCompile(`^AT\+CSYSSEL=\?`), "hangs the channel on this firmware"},
	{regexp.MustCompile(`^AT\+S(?:P)?IMEI=`), "IMEI write: identity material - illegal to alter in most jurisdictions, and a bad value breaks network attach"},
	{regexp.MustCompile(`^AT\+CNVW=`), "NV write by number: persistent modem state, backup required first"},
	{regexp.MustCompile(`^AT\+CNV=.*,\s*[123]\s*(,|$)`), "NV write by path: persistent modem state, backup required first"},
	{regexp.MustCompile(`^AT\+CLCK=`), "SIM lock / barring: can lock the SIM out of the network"},
	{regexp.MustCompile(`^AT\+CPWD=`), "PIN change: can lock the SIM"},
	{regexp.MustCompile(`^AT&F`), "resets AT settings; the vendor app owns this"},
	{regexp.MustCompile(`^AT\+SFUN=`), "SIM/function control: can disable the SIM slot"},
}

// Commands that change modem policy. They need an explicit opt-in because they
// drop the data session, and a wrong band/cell lock leaves the unit unable to
// attach until it is undone - over the network you are most likely managing it
// through.
var atPolicy = []*regexp.Regexp{
	regexp.MustCompile(`^AT\+CSYSSEL=`),
	regexp.MustCompile(`^AT\+CCELLCFG=`),
	regexp.MustCompile(`^AT\+C5GCELLCFG=`),
	regexp.MustCompile(`^AT\+CNMP=`),
	regexp.MustCompile(`^AT\+CMCFG=`),
	regexp.MustCompile(`^AT\+CGDCONT=`),
	regexp.MustCompile(`^AT\+CGAUTH=`),
	regexp.MustCompile(`^AT\+CGACT=`),
	regexp.MustCompile(`^AT\+COPS=`),
	regexp.MustCompile(`^AT\+CFUN=`),
	regexp.MustCompile(`^AT\+CAVIMS=`),
	regexp.MustCompile(`^AT\+VOLTESETTING=`),
	regexp.MustCompile(`^AT\+CRESET`),
	regexp.MustCompile(`^AT\+CPOF`),
	regexp.MustCompile(`^AT\+CUSD=`),
	regexp.MustCompile(`^AT\+CNWSEARCH=`),
	regexp.MustCompile(`^AT\+SPCONFIGSIMSLOT=`),
}

// ClassifyAT decides what may be sent.
func ClassifyAT(cmd string, allowWrites bool) (forbidden bool, needsOptIn bool, reason string) {
	up := strings.ToUpper(strings.TrimSpace(cmd))
	for _, f := range atForbidden {
		if f.pat.MatchString(up) {
			return true, false, f.why
		}
	}
	for _, p := range atPolicy {
		if p.MatchString(up) {
			if !allowWrites {
				return false, true, "changes modem policy; re-run with -write"
			}
			return false, false, ""
		}
	}
	_ = allowWrites
	return false, false, ""
}

// ATHazard returns a warning for commands that are legal but have a side effect
// worth stating before they are sent.
//
// AT+CFUN=1,1 is the sharp one: it resets the modem, which drops the AT channel
// for tens of seconds, and the dialer counts failed AT sends - its failure path
// is "Dialer reboot system cause AT send failed more than %d times" (device repo
// docs/05). So a router reboot is a documented RISK of this command, not
// something observed here (the reboot seen during testing was manual). Use
// AT+CFUN=4 (RF off) when that is what you actually want.
func ATHazard(cmd string) string {
	up := strings.ToUpper(strings.TrimSpace(cmd))
	switch {
	case strings.HasPrefix(up, "AT+CFUN=1,1"):
		return "resets the modem and drops the AT channel; can trip the dialer's AT-failure watchdog, which reboots the router (documented risk, not reproduced here). Prefer AT+CFUN=4"
	case strings.HasPrefix(up, "AT+CFUN=7"):
		return "needs AT+CFUN=6 or a reboot to recover; the device repo says never to send this"
	case strings.HasPrefix(up, "AT+CRESET"), strings.HasPrefix(up, "AT+CPOF"):
		return "drops the modem; the reply may arrive before the channel closes"
	case strings.HasPrefix(up, "AT+CNWSEARCH"), strings.HasPrefix(up, "AT+SPNCELLSCAN"):
		return "blocking network scan; holds the shared AT channel for up to ~2 min"
	}
	return ""
}

// AT is a modem console built on the injected root shell.
type AT struct {
	Shell *Shell
	// AllowWrites permits policy commands (band/cell lock, PDP, ...). It never
	// permits the forbidden set.
	AllowWrites bool
}

// shellQuote wraps a command for the device's sh. AT commands use double quotes
// internally, so single-quoting the argument is enough.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Run sends one AT command and parses the reply.
func (a *AT) Run(cmd string) (ATResult, error) {
	res := ATResult{Cmd: cmd}
	forbidden, optIn, reason := ClassifyAT(cmd, a.AllowWrites)
	if forbidden {
		res.Forbidden = true
		res.Reason = reason
		return res, nil
	}
	if optIn {
		res.Forbidden = true
		res.Reason = reason
		return res, nil
	}

	remote := fmt.Sprintf("timeout -s KILL %d %s %s", ATCmdTimeout, ATCmdBin, shellQuote(cmd))
	out, code, err := a.Shell.Run(remote)
	res.Raw = out
	parseATReply(&res, out)
	if err != nil {
		return res, err
	}
	// atcmd exits 0 even when the modem answers ERROR, so the code only tells us
	// about the channel, not the command.
	_ = code
	return res, nil
}

// parseATReply strips atcmd's own echo and the trailing OK/ERROR.
//
// Observed shapes:
//
//	atcmd_receive:\n861702085648268\n\nOK
//	atcmd_receive:\n+ICCID: 8941...\n\nOK
//	atcmd_receive:\nERROR\n
func parseATReply(res *ATResult, out string) {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	started := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if !started {
			// Everything up to and including atcmd's banner is noise.
			if strings.HasPrefix(t, "atcmd_receive:") {
				started = true
				continue
			}
			if t == "" || strings.HasPrefix(t, "AT+") || strings.HasPrefix(t, "AT") && len(t) <= 4 {
				continue
			}
			started = true
		}
		switch {
		case t == "":
			continue
		case strings.EqualFold(t, "OK"):
			res.OK = true
			return
		case strings.HasPrefix(t, "+CME ERROR"):
			res.Error = t
			return
		case strings.EqualFold(t, "ERROR"):
			res.Error = "ERROR"
			return
		case strings.HasPrefix(t, "timeout"), strings.HasPrefix(t, "sh:"):
			res.Error = t
			return
		default:
			res.Payload = append(res.Payload, t)
		}
	}
}

// NVText decodes a hex NV payload to text when it is meaningfully printable.
// NV items are frequently binary, so this returns "" rather than mojibake.
func NVText(h string) string {
	t := hexToText(h)
	printable := 0
	for _, r := range t {
		if r >= 32 && r < 127 {
			printable++
		}
	}
	if printable < 3 || printable*2 < len(t) {
		return ""
	}
	return t
}

// hexToText decodes the zero-padded hex blob that +CNVR answers with.
func hexToText(h string) string {
	var b strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		hi, ok1 := hexVal(h[i])
		lo, ok2 := hexVal(h[i+1])
		if !ok1 || !ok2 {
			continue
		}
		v := hi<<4 | lo
		if v == 0 {
			continue // padding
		}
		if v >= 32 && v < 127 {
			b.WriteByte(v)
		}
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ReadNV reads an NV item by number (AT+CNVR) or by EFS path (AT+CNV), read
// operation only. Returns the hex and, when it is printable, the decoded text.
func (a *AT) ReadNV(item string, byPath bool) (string, string, error) {
	var cmd string
	if byPath {
		cmd = fmt.Sprintf("AT+CNV=%s,0", item)
	} else {
		cmd = fmt.Sprintf("AT+CNVR=%s,0", item)
	}
	res, err := a.Run(cmd)
	if err != nil {
		return "", "", err
	}
	if !res.OK {
		return "", "", fmt.Errorf("zlt: %s failed: %s", cmd, res.Error)
	}
	hexStr := extractNVPayload(res.Single())
	return hexStr, NVText(hexStr), nil
}

// extractNVPayload pulls the data field out of the two reply shapes.
//
//	+CNVR: 1,"4D5030363234...0000"      <- by number, quoted hex blob
//	+CNV: 8,0,8,1500000820010000        <- by path,  <a>,<op>,<len>,<hex>
func extractNVPayload(line string) string {
	line = strings.TrimSpace(line)
	for _, p := range []string{"+CNVR:", "+CNV:"} {
		if strings.HasPrefix(line, p) {
			line = strings.TrimSpace(strings.TrimPrefix(line, p))
			break
		}
	}
	if i := strings.Index(line, `"`); i >= 0 {
		if j := strings.LastIndex(line, `"`); j > i {
			return line[i+1 : j]
		}
	}
	if i := strings.LastIndex(line, ","); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return line
}

// DeviceIdentity is the read-only summary `info` prints.
type DeviceIdentity struct {
	IMEI      string
	ICCID     string
	IMSI      string
	ModuleSN  string
	Firmware  string
	BuildDate string
}

// ReadIdentity gathers identity fields with queries only.
func (a *AT) ReadIdentity() DeviceIdentity {
	var id DeviceIdentity
	if r, err := a.Run("AT+CGSN"); err == nil && r.OK {
		id.IMEI = r.Single()
	}
	if r, err := a.Run("AT+CICCID"); err == nil && r.OK {
		id.ICCID = strings.TrimSpace(strings.TrimPrefix(r.Single(), "+ICCID:"))
	}
	if r, err := a.Run("AT+CIMI"); err == nil && r.OK {
		id.IMSI = r.Single()
	}
	if _, txt, err := a.ReadNV("2497", false); err == nil {
		id.ModuleSN = txt
	}
	return id
}
