package zlt

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SSH is NOT included in the firmware.
//
// `unlock` only gives you a passwordless busybox telnetd. The stock image has no
// SSH server at all (`find / -name '*dropbear*'` is empty, there is no opkg
// feed), so reaching the box over ssh is a *second*, separate step: transplant a
// dropbear binary, generate host keys, wire it into the boot path, open the
// firewall and start it. That is what StartSSH does.
//
// Everything below mirrors the sequence that was proven on X16-OMN247 (see
// docs/10-access-and-ssh.md in the zlt-x16 repo). Two details matter and are
// easy to get wrong:
//
//  1. TZApp rebuilds iptables at boot and installs
//       -A nmap_scan -p tcp --dport 22 --tcp-flags ALL SYN -j DROP
//     so dropbear listening is not enough - an ACCEPT must be inserted *after*
//     TZApp has run, which is why the allow rule lives in start_ssh.
//  2. dropbear refuses authorized_keys when $HOME is group/world-writable.
//     /home/root is 0775 on a read-only ubifs, so root's home must move to
//     /data/root (0700) or key auth silently fails.

const (
	// DropbearPath is on the writable /data volume because / is read-only ubifs.
	DropbearPath = "/data/ssh/dropbear"
	// DropbearKeyDir holds the host keys.
	DropbearKeyDir = "/data/ssh"
	// StartSSHScript is idempotent and is what the boot path calls.
	StartSSHScript = "/etc/initscripts/start_ssh"
	// StartTZApp is the vendor boot hook that must call the script.
	StartTZApp = "/etc/initscripts/StartTZApp"
	// SSHSwitchKey gates the service exactly the way SYS_TELNET_SWITCH gates the
	// vendor's own telnet.
	SSHSwitchKey = "SYS_SSH_SWITCH"
)

// startSSHScript is the start_ssh body, kept byte-compatible with the copy in the
// zlt-x16 repo (router-fix/start_ssh).
const startSSHScript = `#! /bin/sh
#
# ZLT X16 - Dropbear SSH startup, mirroring /etc/initscripts/start_telnet
# Wired: TZApp.service -> /etc/initscripts/StartTZApp -> start_ssh start
# Gated on mdlcfg SYS_SSH_SWITCH (mdlcfg -a SYS_SSH_SWITCH=0 && mdlcfg -c turns
# it off the same way the vendor switch turns telnet off).
#
set +e

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

CFG=/bin/mdlcfg
SSH_SW=` + "`" + `$CFG -g SYS_SSH_SWITCH` + "`" + `
[ -z "$SSH_SW" ] && SSH_SW=1

DROPBEAR=/data/ssh/dropbear
KEYDIR=/data/ssh
PIDFILE=/var/run/dropbear.pid
PORT=22

allow_firewall() {
    iptables -C INPUT -i bridge0 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT 1 -i bridge0 -p tcp --dport "$PORT" -j ACCEPT
}

start_ssh() {
    if [ -x "$DROPBEAR" ] && [ -f "$KEYDIR/dropbear_rsa_host_key" ]; then
        allow_firewall
        if ! pidof dropbear >/dev/null 2>&1; then
            "$DROPBEAR" -r "$KEYDIR/dropbear_rsa_host_key" \
                        -r "$KEYDIR/dropbear_ed25519_host_key" \
                        -p "$PORT" -P "$PIDFILE"
        fi
    fi
}

stop_ssh() {
    killall dropbear 2>/dev/null
    iptables -D INPUT -i bridge0 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null
}

case "$1" in
    start)   [ "$SSH_SW" = "1" ] && start_ssh ;;
    stop)    stop_ssh ;;
    restart) stop_ssh; sleep 1; [ "$SSH_SW" = "1" ] && start_ssh ;;
    *)       echo "Usage: start_ssh { start | stop | restart }" >&2; exit 1 ;;
esac
exit 0
`

// SSHOptions controls the bootstrap.
type SSHOptions struct {
	// Dropbear is the local path to an ARM32 hard-float dropbear binary. It is
	// only uploaded when the device does not already have one. The toolkit does
	// not ship a binary: it must come from a device on the same SoC/userspace.
	Dropbear string
	// AuthorizedKeys is an optional authorized_keys blob to install for root.
	AuthorizedKeys []byte
	// Port is the SSH port the script should serve (the script pins 22).
	Port int
	// Force re-uploads dropbear even if one is already present.
	Force bool
}

// SSHBootstrap drives the device over the injected telnet shell.
type SSHBootstrap struct {
	Shell  *Shell
	Opts   SSHOptions
	Log    func(format string, args ...any)
	DryRun bool
}

func (b *SSHBootstrap) logf(format string, args ...any) {
	if b.Log != nil {
		b.Log(format, args...)
	}
}

// step runs one command and fails loudly, since a half-applied SSH bootstrap is
// worse than none (it can lock the operator out of the only console).
func (b *SSHBootstrap) step(desc, cmd string) (string, error) {
	b.logf("  %-46s %s", desc, truncateStr(cmd, 90))
	if b.DryRun {
		return "", nil
	}
	out, code, err := b.Shell.Run(cmd)
	if err != nil {
		return out, fmt.Errorf("%s: %w", desc, err)
	}
	if code != 0 {
		return out, fmt.Errorf("%s: exit %d: %s", desc, code, strings.TrimSpace(out))
	}
	return out, nil
}

// Run performs the bootstrap and returns the ordered list of actions taken, so
// the operator can replay or audit them.
func (b *SSHBootstrap) Run(dropbearBinary []byte) ([]string, error) {
	var done []string
	note := func(s string) { done = append(done, s) }

	// 0. Sanity: are we actually root?
	if !b.DryRun {
		out, err := b.step("check root", "id -u")
		if err != nil {
			return done, err
		}
		if strings.TrimSpace(out) != "0" {
			return done, fmt.Errorf("zlt: shell is not root (id -u = %q)", strings.TrimSpace(out))
		}
		note("confirmed uid 0 over the injected shell")
	}

	// 1. Does the device already carry a dropbear? /data survives reboots, so a
	//    previous bootstrap only needs re-wiring.
	hasDropbear := false
	// Read-only probe, so it runs even under -dry-run.
	if _, code, _ := b.Shell.Run("test -x " + DropbearPath); code == 0 {
		hasDropbear = true
	}
	if hasDropbear && !b.Opts.Force {
		b.logf("  %-46s %s", "dropbear already present", DropbearPath)
		note("reused existing " + DropbearPath)
	} else {
		if len(dropbearBinary) == 0 {
			return done, fmt.Errorf(
				"zlt: no dropbear binary supplied and none at %s.\n"+
					"The firmware ships no SSH server. Supply an ARM32 hard-float dropbear "+
					"(-dropbear /path/to/dropbear); it can be lifted from another "+
					"SDX65/glibc-2.31 unit such as a GreenPacket O5A", DropbearPath)
		}
		if _, err := b.step("mkdir /data/ssh", "mkdir -p "+DropbearKeyDir); err != nil {
			return done, err
		}
		if b.DryRun {
			note("would upload dropbear to " + DropbearPath)
		} else {
			if _, _, err := b.Shell.RunUpload(strings.NewReader(string(dropbearBinary)), DropbearPath, "0755"); err != nil {
				return done, fmt.Errorf("upload dropbear: %w", err)
			}
			note(fmt.Sprintf("uploaded dropbear (%d bytes) to %s", len(dropbearBinary), DropbearPath))
		}
	}

	// 2. Host keys. Never hand dropbear an OpenSSH PEM: it fails with
	//    "Early exit: String too long".
	if _, err := b.step("chmod 755 dropbear", "chmod 755 "+DropbearPath); err != nil {
		return done, err
	}
	for _, k := range []struct{ kind, path string }{
		{"rsa", DropbearKeyDir + "/dropbear_rsa_host_key"},
		{"ed25519", DropbearKeyDir + "/dropbear_ed25519_host_key"},
	} {
		exists := false
		if _, code, _ := b.Shell.Run("test -f " + k.path); code == 0 {
			exists = true
		}
		if exists {
			b.logf("  %-46s %s", "host key present", k.path)
			continue
		}
		keygen := "dropbearkey"
		if _, code, _ := b.Shell.Run("command -v dropbearkey"); code != 0 {
			keygen = DropbearKeyDir + "/dropbearkey"
		}
		cmd := fmt.Sprintf("%s -t %s -f %s", keygen, k.kind, k.path)
		if _, err := b.step("generate "+k.kind+" host key", cmd); err != nil {
			return done, err
		}
		note("generated " + k.kind + " host key")
	}
	if _, err := b.step("chmod 600 host keys", "chmod 600 "+DropbearKeyDir+"/dropbear_*_host_key"); err != nil {
		return done, err
	}

	// 3. Root's home must not be group/world-writable or key auth is refused.
	//    /home/root is 0775 on read-only ubifs, so move it to /data/root.
	if _, err := b.step("ensure /data/root 0700", "mkdir -p /data/root && chmod 700 /data/root && mkdir -p /data/root/.ssh && chmod 700 /data/root/.ssh"); err != nil {
		return done, err
	}
	home := "/data/root"
	if !b.DryRun {
		home, _ = b.step("read root home", "awk -F: '$1==\"root\"{print $6}' /etc/passwd")
	}
	if strings.TrimSpace(home) != "/data/root" {
		if _, err := b.step("repoint root home to /data/root",
			`sed -i 's#^root:x:0:0:root:/home/root:#root:x:0:0:root:/data/root:#' /etc/passwd`); err != nil {
			return done, err
		}
		note("/etc/passwd: root home -> /data/root (dropbear key auth needs a 0700 home)")
	}

	if len(b.Opts.AuthorizedKeys) > 0 {
		if b.DryRun {
			note("would install authorized_keys")
		} else {
			if _, _, err := b.Shell.RunUpload(strings.NewReader(string(b.Opts.AuthorizedKeys)), "/data/root/.ssh/authorized_keys", "0600"); err != nil {
				return done, fmt.Errorf("install authorized_keys: %w", err)
			}
			note("installed /data/root/.ssh/authorized_keys")
		}
	}

	// 4. Boot wiring: the vendor's own pattern.
	if b.DryRun {
		note("would write " + StartSSHScript)
	} else {
		if _, _, err := b.Shell.RunUpload(strings.NewReader(startSSHScript), StartSSHScript, "0755"); err != nil {
			return done, fmt.Errorf("write %s: %w", StartSSHScript, err)
		}
		note("wrote " + StartSSHScript + " (0755)")
	}

	// Patch StartTZApp to call it, keeping a backup, idempotently.
	if _, err := b.step("hook start_ssh into StartTZApp",
		`grep -q 'initscripts/start_ssh' `+StartTZApp+` || `+
			`(cp -n `+StartTZApp+` `+StartTZApp+`.orig; `+
			`printf '\n### ssh\n`+"`"+`dirname $0`+"`"+`/start_ssh start\n' >> `+StartTZApp+`)`); err != nil {
		return done, err
	}
	note("hooked " + StartSSHScript + " into " + StartTZApp)

	// 5. Switch + persist. `mdlcfg -a` then `-c`, exactly like the docs.
	if _, err := b.step("enable "+SSHSwitchKey, "mdlcfg -a "+SSHSwitchKey+"=1 && mdlcfg -c"); err != nil {
		return done, err
	}
	note("mdlcfg " + SSHSwitchKey + "=1 (persisted)")

	// 6. Start it now and open the firewall ahead of TZApp's nmap_scan DROP.
	if _, err := b.step("start_ssh start", StartSSHScript+" start"); err != nil {
		return done, err
	}
	note("started dropbear on tcp/22 with an ACCEPT ahead of nmap_scan")

	// 7. Confirm it is really listening.
	if !b.DryRun {
		out, code, _ := b.Shell.Run("netstat -lnt 2>/dev/null | grep -c ':22 '")
		if code != 0 || strings.TrimSpace(out) == "0" {
			ln, _, _ := b.Shell.Run("netstat -lnt 2>/dev/null")
			return done, fmt.Errorf("zlt: dropbear did not bind tcp/22. listeners:\n%s", ln)
		}
		note("tcp/22 is listening")
	}
	return done, nil
}

// VerifySSH checks the port from the caller's side.
func VerifySSH(host string, port int, timeout time.Duration) bool {
	if port == 0 {
		port = 22
	}
	return PortOpen(host, port, timeout)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// SortedKeys is a tiny helper used by callers that log option maps.
func SortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
