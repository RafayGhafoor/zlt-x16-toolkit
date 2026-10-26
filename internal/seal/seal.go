// Package seal provides build-time sealed string constants.
//
// The build step (tools/genseal) encrypts selected literals with AES-256-GCM
// under a per-build random key and emits internal/zlt/sealed_gen.go containing
// only base64 ciphertext. At runtime the constants are opened in memory.
//
// IMPORTANT: this is obfuscation, not cryptographic protection. The key ships
// inside the binary, so a determined analyst can recover every literal. Its only
// purpose is to keep endpoints, payload text and default credentials out of
// casual inspection (`strings`, `grep`, crash dumps, support bundles).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log"
)

// Open decrypts a base64 AES-256-GCM ciphertext produced by tools/genseal.
// It never panics; on any failure it returns an empty string and logs, so a
// corrupted blob degrades to "feature disabled" rather than a crash on a
// remote device.
func Open(b64, keyHex string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 12 {
		log.Printf("seal: bad blob: %v", err)
		return ""
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Printf("seal: bad key")
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("seal: cipher: %v", err)
		return ""
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("seal: gcm: %v", err)
		return ""
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		log.Printf("seal: open: %v", err)
		return ""
	}
	return string(plain)
}

// Seal is the inverse, used by the generator and tests.
func Seal(plaintext, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Random nonce: a deterministic one would make identical plaintexts
	// produce identical ciphertexts (e.g. default user == default password).
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}
