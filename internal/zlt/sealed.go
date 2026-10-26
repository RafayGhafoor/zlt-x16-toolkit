package zlt

import (
	"fmt"
	"strings"

	"github.com/RafayGhafoor/zlt-x16-toolkit/internal/seal"
)

// Sensitive literals are sealed at build time by tools/genseal and opened in
// init(). There are deliberately NO plaintext fallbacks: if the sealed blobs are
// missing or corrupt the values come back empty and See sanityCheck().
//
// The sealed* names are defined in sealed_gen.go (generated, do not edit).

var (
	// DefaultCGIPath is the single CGI entry point the web UI uses.
	DefaultCGIPath string
	// DefaultDMZHost is a plausible DMZ address placed before the ';'.
	DefaultDMZHost string
	// DefaultUser / DefaultPass are the firmware's shipped web credentials.
	DefaultUser string
	DefaultPass string
	// DefaultHost is the device's factory LAN address.
	DefaultHost string
	// noAuthMarker is what the device returns for an expired session.
	noAuthMarker string
	// superUserName is the highest-privilege built-in account.
	superUserName string

	// telnetTmpl builds the passwordless-shell payload.
	telnetTmpl string
)

// Sealed reports whether the sealed constants were successfully opened.
func Sealed() bool { return sanityCheck() == nil }

func sanityCheck() error {
	missing := []string{}
	for name, v := range map[string]string{
		"DefaultCGIPath": DefaultCGIPath,
		"DefaultHost":    DefaultHost,
		"telnetTmpl":     telnetTmpl,
		"noAuthMarker":   noAuthMarker,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("sealed constants unavailable (%s); run 'make seal' and rebuild", strings.Join(missing, ", "))
	}
	return nil
}

func init() {
	DefaultCGIPath = seal.Open(sealedCGIPath, sealedKey)
	DefaultDMZHost = seal.Open(sealedDmzHost, sealedKey)
	DefaultUser = seal.Open(sealedDefaultUser, sealedKey)
	DefaultPass = seal.Open(sealedDefaultPass, sealedKey)
	DefaultHost = seal.Open(sealedDefaultHost, sealedKey)
	noAuthMarker = seal.Open(sealedNoAuthMarker, sealedKey)
	superUserName = seal.Open(sealedSuperUser, sealedKey)
	telnetTmpl = seal.Open(sealedTelnetTmpl, sealedKey)
}
