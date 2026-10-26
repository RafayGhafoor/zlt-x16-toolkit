package zlt

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one device's web management API.
type Client struct {
	base string
	lang string
	http *http.Client
	// SessionID is set after a successful Login and sent on every request.
	SessionID string
	// Level is the account tier ("1"/"2"/"3") reported by the device.
	Level string
}

// NewClient builds a client for the given origin (e.g. "http://192.168.3.1").
func NewClient(base, lang string, timeout time.Duration, insecure bool) (*Client, error) {
	if base == "" {
		return nil, fmt.Errorf("zlt: base URL is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("zlt: bad base URL %q: %w", base, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("zlt: base URL %q needs a scheme and host", base)
	}
	if lang == "" {
		lang = "en"
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	return &Client{
		base: strings.TrimRight(base, "/"),
		lang: lang,
		http: &http.Client{Timeout: timeout, Transport: tr},
	}, nil
}

// URLFor builds the CGI URL for a command. The device's JS passes cmd, method,
// sessionId and language as query parameters, and repeats them in the JSON body.
func (c *Client) URLFor(cmd int, method string) string {
	q := url.Values{}
	q.Set("cmd", fmt.Sprint(cmd))
	q.Set("method", method)
	q.Set("sessionId", c.SessionID)
	q.Set("language", c.lang)
	return c.base + DefaultCGIPath + "?" + q.Encode()
}

// Do sends one JSON request and returns the raw response body.
func (c *Client) Do(cmd int, method string, body any) ([]byte, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("zlt: marshal request: %w", err)
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.URLFor(cmd, method), payload)
	if err != nil {
		return nil, fmt.Errorf("zlt: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", c.base+"/login.html")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zlt: %s cmd=%d: %w", method, cmd, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("zlt: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("zlt: cmd=%d http %d", cmd, resp.StatusCode)
	}
	return out, nil
}

// DoJSON sends a request and decodes the response into out.
func (c *Client) DoJSON(cmd int, method string, body, out any) error {
	raw, err := c.Do(cmd, method, body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("zlt: cmd=%d returned an empty body", cmd)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("zlt: cmd=%d decode %q: %w", cmd, truncate(raw, 160), err)
	}
	return nil
}

// FetchToken performs cmd=232 (GET_NEXT_LOGIN_TIME) which returns the salt the
// UI hashes into the password before submitting.
func (c *Client) FetchToken() (string, error) {
	body := map[string]any{
		"cmd":       CmdGetNextLoginTime,
		"method":    "GET",
		"sessionId": "",
	}
	var tr TokenResult
	if err := c.DoJSON(CmdGetNextLoginTime, "GET", body, &tr); err != nil {
		return "", err
	}
	return tr.Token, nil
}

// HashPassword reproduces the browser's password transform:
//
//	passwd = sha256_hex(token + password)
func HashPassword(token, password string) string {
	sum := sha256.Sum256([]byte(token + password))
	return hex.EncodeToString(sum[:])
}

// Login authenticates with username/password. It mirrors /tzwww/js/login.js:
// fetch a token, then POST cmd=100 with sha256(token+password).
func (c *Client) Login(username, password string) (LoginResult, error) {
	token, err := c.FetchToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("zlt: login token step: %w", err)
	}

	c.SessionID = randomSessionID()
	body := map[string]any{
		"cmd":           CmdLogin,
		"method":        "POST",
		"sessionId":     c.SessionID,
		"username":      username,
		"passwd":        HashPassword(token, password),
		"isAutoUpgrade": "0",
	}
	var res LoginResult
	if err := c.DoJSON(CmdLogin, "POST", body, &res); err != nil {
		return res, err
	}
	if res.SessionID != "" {
		c.SessionID = res.SessionID
	}
	if res.UserLevel != "" {
		c.Level = res.UserLevel
	}
	return res, nil
}

// randomSessionID mirrors the browser's Md5(random)+Md5(random) pre-login id.
// Uniqueness is all that matters here.
func randomSessionID() string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 32)
	for i := range b {
		b[i] = hexdigits[rand.Intn(len(hexdigits))]
	}
	return string(b)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
