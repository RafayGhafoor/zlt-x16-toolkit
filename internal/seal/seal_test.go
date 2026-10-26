package seal

import (
	"encoding/hex"
	"strings"
	"testing"
)

func testKey() string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return hex.EncodeToString(k)
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey()
	for _, plain := range []string{"", "a", "/cgi-bin/http.cgi", strings.Repeat("x", 4096)} {
		blob, err := Seal(plain, key)
		if err != nil {
			t.Fatalf("seal %q: %v", plain, err)
		}
		if got := Open(blob, key); got != plain {
			t.Fatalf("round trip: got %q want %q", got, plain)
		}
	}
}

func TestSealNonceIsRandom(t *testing.T) {
	key := testKey()
	a, _ := Seal("same", key)
	b, _ := Seal("same", key)
	if a == b {
		t.Fatal("identical plaintexts must not produce identical ciphertexts")
	}
	if Open(a, key) != Open(b, key) {
		t.Fatal("both must still decrypt to the same value")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	blob, _ := Seal("secret", testKey())
	other := strings.Repeat("ab", 32)
	if got := Open(blob, other); got != "" {
		t.Fatalf("wrong key must fail closed, got %q", got)
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "!!!notbase64!!!", "AAAA", "YWJj"} {
		if got := Open(bad, testKey()); got != "" {
			t.Fatalf("garbage %q must fail closed", bad)
		}
	}
}

func TestOpenRejectsShortBlob(t *testing.T) {
	if got := Open("AAAA", testKey()); got != "" {
		t.Fatal("blob shorter than a nonce must fail closed")
	}
}

func TestPlaintextNotPresentInCiphertext(t *testing.T) {
	block, _ := Seal("/cgi-bin/http.cgi", testKey())
	if strings.Contains(block, "http.cgi") {
		t.Fatal("plaintext leaked into the blob")
	}
}
