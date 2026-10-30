package zlt

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// The injected daemon is `busybox telnetd -l /bin/sh`, i.e. telnet with the
// login program replaced by a shell. That makes it both a root shell and an
// annoyance: the stream is full of telnet option negotiation (IAC) bytes and
// there is no exit-status channel. This file wraps it well enough to script the
// bootstrap steps that the web API cannot do (writing files, installing
// dropbear, wiring a service).

const (
	iac  = 255 // "interpret as command"
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250 // subnegotiation begin
	se   = 240 // subnegotiation end
)

// Shell is a root console on an already-provisioned device.
type Shell struct {
	Addr    string
	Timeout time.Duration

	conn net.Conn
	rd   *bufio.Reader
}

// DialShell connects and puts the stream into a usable state by refusing every
// telnet option the daemon offers.
func DialShell(addr string, timeout time.Duration) (*Shell, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("zlt: dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	s := &Shell{Addr: addr, Timeout: timeout, conn: conn, rd: bufio.NewReader(conn)}
	if err := s.negotiate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.quiet()
	return s, nil
}

// quiet disables terminal echo.
//
// This is not cosmetic. The daemon runs the shell on a pty, so every command we
// send is echoed straight back. If the command text contains the output
// sentinels - and it always does - the echoed copy matches before the real
// output arrives and the parser returns the wrong slice. Turning echo off makes
// the sentinel unambiguous.
func (s *Shell) quiet() {
	_, _ = s.conn.Write([]byte("stty -echo 2>/dev/null; PS1=; PS2=\n"))
	// Drain whatever the pty already queued (the echoed stty line, any banner).
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = s.conn.SetReadDeadline(deadline)
		if _, err := s.rd.ReadByte(); err != nil {
			break
		}
	}
}

// negotiate drains the initial IAC burst and refuses options so the daemon stops
// talking protocol at us.
func (s *Shell) negotiate() error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := s.rd.Peek(1)
		if err != nil || len(b) == 0 || b[0] != iac {
			return nil
		}
		cmd, err := s.rd.ReadByte()
		if err != nil {
			return err
		}
		if cmd != iac {
			continue
		}
		opt, err := s.rd.ReadByte()
		if err != nil {
			return err
		}
		switch opt {
		case will, wont, do, dont:
			code, err := s.rd.ReadByte()
			if err != nil {
				return err
			}
			var reply byte
			switch opt {
			case will, do:
				reply = dont // refuse everything
			default:
				reply = wont
			}
			_, _ = s.conn.Write([]byte{iac, reply, code})
		case sb:
			// Drain until IAC SE.
			for {
				c, err := s.rd.ReadByte()
				if err != nil {
					return err
				}
				if c == iac {
					n, err := s.rd.ReadByte()
					if err != nil {
						return err
					}
					if n == se {
						break
					}
				}
			}
		case iac:
		default:
			// NOP / GA / etc.
		}
	}
	return nil
}

// Close releases the connection.
func (s *Shell) Close() error { return s.conn.Close() }

// script wraps a command in unique sentinels so the reply can be sliced out of
// the stream without trusting a prompt string. The tag is random per call, so a
// stale match from a previous command can never be picked up.
func script(tag, body string) string {
	return fmt.Sprintf("echo %s%s; %s; echo %s%s $?\n", ShellBegin, tag, body, ShellEnd, tag)
}

// Sentinels. Random tag plus these prefixes is unique enough.
const (
	ShellBegin = "__Z_B_"
	ShellEnd   = "__Z_E_"
)

// Run executes one shell command and returns its combined stdout/stderr.
func (s *Shell) Run(command string) (string, int, error) {
	if strings.ContainsAny(command, "\n\r") {
		return "", -1, fmt.Errorf("zlt: shell command must be a single line")
	}
	tag := randomSessionID()[:12]
	if err := s.write(script(tag, command)); err != nil {
		return "", -1, err
	}
	return s.readResult(tag)
}

// RunUpload streams a file to remotePath using base64 in chunks. The device's
// busybox base64 has no -w flag and there is no sftp server, so chunked
// heredocs are the only reliable path.
func (s *Shell) RunUpload(r io.Reader, remotePath string, mode string) (string, int, error) {
	if mode == "" {
		mode = "0755"
	}
	dir := remotePath
	if i := strings.LastIndex(remotePath, "/"); i > 0 {
		dir = remotePath[:i]
	}
	if _, code, err := s.Run(fmt.Sprintf("mkdir -p %s && : > %s", dir, remotePath)); err != nil || code != 0 {
		return "", code, fmt.Errorf("zlt: prepare %s failed (code %d): %w", remotePath, code, err)
	}

	const chunk = 4096
	buf := make([]byte, chunk)
	total := 0
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			enc := base64.StdEncoding.EncodeToString(buf[:n])
			cmd := fmt.Sprintf("printf %%s %s | base64 -d >> %s", enc, remotePath)
			if _, code, cerr := s.Run(cmd); cerr != nil || code != 0 {
				return "", code, fmt.Errorf("zlt: upload chunk at %d failed (code %d): %w", total, code, cerr)
			}
			total += n
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", -1, err
		}
	}
	out, code, err := s.Run(fmt.Sprintf("chmod %s %s && wc -c < %s", mode, remotePath, remotePath))
	return out + fmt.Sprintf("(%d bytes sent)", total), code, err
}

func (s *Shell) write(cmd string) error {
	// Strip the telnet line-mode ambiguity: send CRLF, not LF.
	_ = s.conn.SetDeadline(time.Now().Add(s.Timeout))
	_, err := s.conn.Write([]byte(strings.ReplaceAll(cmd, "\n", "\r\n")))
	return err
}

// readResult reads until the end sentinel and returns the captured body plus the
// exit status echoed after it.
func (s *Shell) readResult(tag string) (string, int, error) {
	begin := ShellBegin + tag
	end := ShellEnd + tag
	deadline := time.Now().Add(s.Timeout)
	var out bytes.Buffer
	for {
		_ = s.conn.SetDeadline(deadline)
		line, err := s.rd.ReadString('\n')
		if line != "" {
			clean := stripIAC(line)
			out.WriteString(clean)
			if strings.Contains(clean, end) {
				return sliceResult(out.String(), begin, end)
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return "", -1, fmt.Errorf("zlt: shell timed out waiting for %s", end)
			}
			return "", -1, fmt.Errorf("zlt: shell read: %w", err)
		}
		if out.Len() > 1<<20 {
			return "", -1, fmt.Errorf("zlt: shell output exceeded 1 MiB")
		}
	}
}

// sliceResult cuts the body out from between the sentinels.
func sliceResult(all, begin, endMark string) (string, int, error) {
	start := strings.Index(all, begin)
	end := strings.Index(all, endMark)
	if start < 0 || end < 0 || end < start {
		return strings.TrimSpace(all), -1, fmt.Errorf("zlt: could not delimit shell output")
	}
	between := all[start+len(begin) : end]
	between = strings.TrimPrefix(between, "\r\n")
	between = strings.TrimPrefix(between, "\n")
	between = strings.TrimSuffix(between, "\r\n")
	between = strings.TrimSuffix(between, "\n")

	// The exit status follows the end sentinel on the same line: "<END> 0".
	rest := strings.TrimLeft(all[end+len(endMark):], " \t")
	num := ""
	for _, r := range rest {
		if r >= '0' && r <= '9' {
			num += string(r)
			continue
		}
		break
	}
	code := -1
	if num != "" {
		if v, err := strconv.Atoi(num); err == nil {
			code = v
		}
	}
	return between, code, nil
}

// stripIAC removes telnet command sequences from a line of output.
func stripIAC(s string) string {
	if !strings.ContainsRune(s, rune(iac)) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != iac {
			b.WriteByte(s[i])
			continue
		}
		// Skip the command byte and, for option commands, the option byte.
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case will, wont, do, dont:
			i += 2
		case sb:
			i++
			for i < len(s) {
				if s[i] == iac && i+1 < len(s) && s[i+1] == se {
					i += 1
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return b.String()
}
