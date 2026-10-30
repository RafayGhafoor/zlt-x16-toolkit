# zlt-x16-toolkit

Provisioning toolkit for **ZLT X16** 5G CPE (Qualcomm SDX65, SIMCom SIM8260E)
that you own or are authorised to administer.

It talks to the device's own web management API, so it needs nothing but network
access to the target's HTTP port.

> **Authorised use only.** `unlock` changes device state and opens an
> unauthenticated root shell. Running it against equipment you do not own or have
> written permission to administer may be unlawful. Every `unlock` invocation
> requires `--confirm`.

---

## What it does

| Command | Effect |
|---|---|
| `probe` | Reachability, open ports, firmware identity |
| `login` | Verify web credentials and print the privilege tier |
| `verify` | Check whether a passwordless shell is already exposed (read-only) |
| `unlock` | Install a passwordless root shell via the device's DMZ handler |
| `exec` | Run one command over an already-provisioned root shell |
| `put` | Upload a file over that shell (chunked base64 - no sftp on the device) |
| `ssh` | Bootstrap dropbear over that shell; the firmware ships **no** SSH server |
| `info` | Read-only identity: IMEI, ICCID, IMSI, module serial, firmware |
| `at` | AT commands via the vendor's serialised `/bin/atcmd` (writes guarded) |
| `nv` | Read an NV item by number or EFS path (read only) |
| `level` | Show/set `account_level` - the flag that gates the web AT console |
| `features` | Inventory the `*_SW` switches; enable the safe set, refuse the harmful one |

Why this works, and the full request/response detail: [docs/protocol.md](docs/protocol.md).

> Credentials are **not** shipped in this repository. The factory and super-admin
> passwords are per-device config values (`SYS_SUPER_LOGIN_PWD` and friends); read
> them off the unit you are authorised to administer and pass them on the command
> line or via `$SUPER_PWD`. Committing a live one would hand every unit of this
> model to whoever reads the repo.

> **The super account is not required.** `admin`/`admin` is sufficient: the DMZ
> handler is gated on session validity, not on account tier. Evidence and the
> decompiled authorisation switch are in
> [docs/protocol.md](docs/protocol.md#privilege-model--the-super-account-is-not-required).
> `unlock -user ''` tries every shipped account in turn.

## Download a binary (no build needed)

Every [release](https://github.com/RafayGhafoor/zlt-x16-toolkit/releases) ships a
static binary per platform, plus `SHA256SUMS.txt`:

| Your machine | Download | Run |
|---|---|---|
| **Windows** 10/11 (64-bit) | `zltx16-windows-amd64.exe` | `zltx16.exe probe -host 192.168.3.1` |
| **macOS** Apple silicon | `zltx16-darwin-arm64` | `./zltx16 probe -host 192.168.3.1` |
| **macOS** Intel | `zltx16-darwin-amd64` | `./zltx16 probe -host 192.168.3.1` |
| **Linux** x86-64 | `zltx16-linux-amd64` | `./zltx16 probe -host 192.168.3.1` |
| **Linux** arm64 (Pi, router) | `zltx16-linux-arm64` | `./zltx16 probe -host 192.168.3.1` |
| **Linux** armv7 (the CPE SoC itself) | `zltx16-linux-arm` | `./zltx16 probe -host 127.0.0.1` |

```sh
# verify what you downloaded, then run it
sha256sum -c SHA256SUMS.txt          # macOS: shasum -a 256 -c SHA256SUMS.txt
chmod +x zltx16-linux-amd64 && ./zltx16-linux-amd64 probe -host 192.168.3.1
```

The binaries are built from the **sealed** source, so `strings` will not reveal the
request surface or the payload - the release job fails the build if it can.

## Install

```bash
git clone <this repo>
cd zlt-x16-toolkit
make test          # Go + Python test suites
make build-enc     # encrypted release build -> dist/zltx16
```

Requires Go 1.22+ (build time only; the binary is static) and Python 3.8+ for the
reference implementation.

## Usage

```bash
# 1. is it there, and what is it?
./dist/zltx16 probe -host 192.168.3.1

# 2. do the credentials work?
./dist/zltx16 login -host 192.168.3.1 -user admin -pass admin

# 3. read-only check: is a passwordless shell already open?
./dist/zltx16 verify -host 192.168.3.1 --ports 23,22

# 4. provision it (opens a root shell on tcp/23)
./dist/zltx16 unlock -host 192.168.3.1 -user admin -pass admin --confirm
```

Higher privilege tiers, or the alternate port when 23 is busy:

```bash
# try every shipped account (admin, then root, then superadmin)
./dist/zltx16 unlock -host 192.168.3.1 -user '' --confirm

./dist/zltx16 unlock -host 192.168.3.1 --mode telnet-alt --dport 4444 --confirm
```

> `-user ''` walks the shipped credential chain. You do not need the super
> account: the ordinary `admin`/`admin` login is enough, because `cmd:172
> subcmd:6` is gated on session validity and not on account tier. See
> [docs/protocol.md](docs/protocol.md#privilege-model--the-super-account-is-not-required).

Run one specific command instead of installing a daemon:

```bash
./dist/zltx16 unlock -host 192.168.3.1 \
  --mode command --cmd 'id > /tmp/.zlt_unlock_marker' --confirm
```

Then use the shell you just got. The port is not always 23 — 2233 has been
observed on unlocked units, so point `-shell` at whatever answers:

```bash
./dist/zltx16 verify -host 192.168.3.1                  # probes 23, 2233, 9876, 22
./dist/zltx16 exec -host 192.168.3.1 -shell 192.168.3.1:2233 'id; uname -a'
./dist/zltx16 put  -host 192.168.3.1 -shell 192.168.3.1:2233 ./dropbear /data/ssh/dropbear
```

### The modem: AT commands and IMEI

Root is what makes the modem reachable. There is no AT device node to open — the
modem is on the same die as the CPU and `atcmd_daemon` owns `/dev/smd8` — so the
toolkit drives the vendor's own serialised client, `/bin/atcmd`, over the root
shell. **No `/etc/shadow` edit is involved anywhere in this.**

```bash
./dist/zltx16 info -host 192.168.3.1 -shell 192.168.3.1:2233
./dist/zltx16 at   -host 192.168.3.1 -shell 192.168.3.1:2233 'AT+CSQ' 'AT+CPSI?'
./dist/zltx16 nv   -host 192.168.3.1 -shell 192.168.3.1:2233 2497
```

One thing that surprises people: the **web** AT console is gated by
`account_level`, not by the shell. `cmd=270 SEND_AT` answers `LIMITED_ACCESS` at
level 3 (where `admin/admin` logs in) and succeeds at level 1. That is the flag a
front shim can force per request — and it is why AT "appears" after some unlocks.
It is not needed for the root shell or for the AT work above.

```bash
./dist/zltx16 level -host 192.168.3.1 -shell 192.168.3.1:2233        # tier + shim state
./dist/zltx16 level -host 192.168.3.1 -shell 192.168.3.1:2233 -set 1 # enable the web AT console
```

`AT+CFUN=1,1` is allowed under `-write` but now warns. It resets the modem and
drops the AT channel, and the device repo's `docs/05` documents the dialer
rebooting the router when AT sends fail repeatedly — a plausible, but here
**unverified**, consequence (the reboot seen during testing was manual). Prefer
`AT+CFUN=4` for RF control.

Separately verified: the saved DMZ payload **re-executes at boot**, so a
provisioned root console survives reboots.

Every AT call is wrapped in `timeout -s KILL` because `atcmd` ignores `SIGTERM` and a
plain timeout leaves the shared AT channel held. `AT+CLAC`, `AT+CFUN?` and
`AT+CSYSSEL=?` are refused — they wedge `atcmd_daemon` for every client on this
firmware.

IMO the IMEI surface has one useful direction and one that should not be built:

| | |
|---|---|
| **Read** (`AT+CGSN`, `AT+SIMEI?`) | what `info` does |
| **Write** (`AT+SIMEI=`, `AT+SPIMEI=`) | **refused** — identity material, illegal to alter in most jurisdictions, and a bad value breaks network attach |

Policy writes that are legitimate on your own unit (band list, cell lock, PDP
profile) need an explicit opt-in:

```bash
./dist/zltx16 at -write -host 192.168.3.1 -shell 192.168.3.1:2233 \
  'AT+CSYSSEL="lte_band",1:3:5:28:38:41'
```

### Getting SSH (a second, separate step)

`unlock` gives you **telnet**, not SSH. The stock image has no SSH server, no
`sftp-server`, and no package feed. The `ssh` subcommand automates the bootstrap
that was done by hand on the reference unit:

```bash
./dist/zltx16 ssh -host 192.168.3.1 -shell 192.168.3.1:2233 \
  -dropbear ./dropbear -authorized-keys ~/.ssh/id_ed25519.pub
```

It reuses a dropbear already present at `/data/ssh/dropbear`, generates host keys
with `dropbearkey`, moves root's home to `/data/root` (dropbear refuses
`authorized_keys` under a group-writable `$HOME`, and `/home/root` is `0775` on a
read-only ubifs), writes `/etc/initscripts/start_ssh`, hooks it into
`StartTZApp`, sets `mdlcfg SYS_SSH_SWITCH=1`, inserts an `iptables ACCEPT` ahead
of TZApp's `nmap_scan` port-22 DROP, starts it, and confirms tcp/22. Add
`-dry-run` to see the steps without touching the device.

The Python twin exposes the same four subcommands:

```bash
python3 python/zltx16_unlock.py probe  -H 192.168.3.1
python3 python/zltx16_unlock.py unlock -H 192.168.3.1 -u admin -p admin --confirm
```

## After you unlock: what this is actually for

The unlock is **step zero**, not the destination. It gives you a root shell so the
device can be provisioned and instrumented. Once this tool has given you a shell,
the companion repository
**[zlt-x16-field-tooling](https://github.com/RafayGhafoor/zlt-x16-field-tooling-public)**
takes over - it deploys the QManager UI, the AT-dialect shim, hardware-offload
supervision, SmartDNS, a browser call terminal, and the guards that keep them up,
all through one idempotent command:

```sh
git clone https://github.com/RafayGhafoor/zlt-x16-field-tooling-public.git
cd zlt-x16-field-tooling
./deploy.sh --dry-run     # what it will do
./deploy.sh               # do it
```

**Order matters: unlock first (this repo), then deploy (the other one).** The deploy
step assumes root access, which is exactly what `unlock` provides.

## Help, updates, walkthroughs

- **Telegram** - questions, setup help, firmware notes: <https://t.me/setids>
- **YouTube** - end-to-end walkthrough: <https://www.youtube.com/watch?v=frmXNgGuJmk>
- **Issues** - reproducible bugs belong in
  [Issues](https://github.com/RafayGhafoor/zlt-x16-toolkit/issues); please include
  `zltx16 probe` output and your OS.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `unlock`: shell confirmed) |
| 1 | Reached the device but it refused / verification failed |
| 2 | Refused locally: bad arguments, or `--confirm` missing |

## The encrypted build

`make build-enc` does **not** ship readable strings.

`tools/genseal` re-encrypts the sensitive literals with **AES-256-GCM** under a
fresh random key and rewrites `internal/zlt/sealed_gen.go` with base64
ciphertext only. The values are opened in memory at `init()`. There are no
plaintext fallbacks in the source — if the blobs are unreadable the tool fails
loudly rather than silently using a default.

What ends up sealed:

| Literal | Why |
|---|---|
| CGI path | the request surface |
| telnet payload template | the injection itself |
| default username / password | shipped credentials |
| senior username / password | fallback credential |
| factory LAN address | default target |
| `NO_AUTH` marker | protocol internals |
| `superadmin` / its password | last-resort fallback credential |

Verify it yourself:

```bash
make verify-enc
```

```
--- literals that MUST be absent from dist/zltx16 ---
  ok     cgi-bin/http.cgi
  ok     busybox telnetd
  ok     NO_AUTH
  ok     192.168.3.1
  ok     superadmin
  ok     telnetd
  ok     RequestCmd
--- control: the plain build must still contain them ---
  ok     plain build leaks as expected
```

**Be clear about what this is.** This is obfuscation, not cryptography. The key
ships inside the binary, so a determined analyst can recover every literal. It
defeats `strings`, `grep`, support bundles and casual inspection — which is the
realistic threat. If you need the tool to be genuinely opaque, the binary must
fetch its configuration from a server you control, and that is a different design.

### `make build-garble` (optional, usually unavailable on macOS)

A stronger option is [garble](https://github.com/burrowers/garble), which
encrypts literals at the compiler level. **It is not the default here because
macOS security software deletes the output.** Observed on this workstation:

- garble 0.18 requires Go ≥ 1.27; the default toolchain was 1.26
- after installing Go 1.27 via `golang.org/dl`, garble builds fine
- but every `-literals` binary is **removed within seconds** of being written,
  for `darwin/arm64`, `linux/arm64`, `linux/amd64` alike
- the plain `go build` output of the same code survives

Run `make build-garble` on Linux if you want that layer.

## Testing

```bash
make test        # go vet + go test + python unittest
make test-go
make test-py
```

Coverage includes the login token/hash handshake, payload construction and its
input validation, the no-auth probe heuristics (including telnet IAC noise),
sealed-literal round-trips, and the full orchestration flow against a fake
device. Nothing in the test suite touches a real router.

## Layout

```
cmd/zltx16/         CLI entry point
internal/zlt/       client, payload, probe, orchestration
internal/seal/      AES-256-GCM sealing
internal/zlt/sealed_gen.go   generated — do not edit
tools/genseal/      regenerates sealed_gen.go
python/             single-file reference implementation + tests
docs/protocol.md    the reverse-engineered protocol
```

## Caveats

- The target must be reachable on its HTTP port. On a factory ZLT X16 the WAN
  firewall drops tcp 22/80/443, so this works from the **LAN** side.
- If the device already has an unauthenticated `telnetd -l /bin/sh` on 23, the
  injected daemon cannot bind and `unlock` reports "injection sent but no shell
  observed" even though you already have a shell. Run `verify` first.
- Firmware varies by operator SKU. The command numbers and the DMZ `subcmd` were
  confirmed on `X16-OMN247` (Ooredoo Oman). If `subcmd` differs on your build,
  the tool will report a rejection rather than guess.

## License

Internal / private. No warranty. Use at your own risk.
