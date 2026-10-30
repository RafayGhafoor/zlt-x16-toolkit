package zlt

import (
	"fmt"
	"sort"
	"strings"
)

// Feature switches
// ================
// Unlocking gives you root, and the front shim gives you account_level=1. Neither
// of those *enables* features: features are gated by plain `mdlcfg` parameters,
// most of which are named `*_SW` / `*_SWITCH` / `*_ENABLE` and hold 0 or 1.
//
// Flipping them all is a bad idea, so each known key carries a class:
//
//	safe    - no security or durability cost. Safe to turn on.
//	risky   - works, but costs something (attack surface, flash wear, an ISP gets
//	          control). Reported, never applied automatically.
//	never   - turning it ON is the harmful direction: it would lock the SIM in,
//	          expose the web UI to the WAN, or hand the device to the operator's
//	          TR-069 server. Refused even when asked for by name.
//
// Anything not in the table is reported as "unknown" and left alone.

// SwitchClass is how much care a switch needs.
type SwitchClass string

const (
	SwitchSafe    SwitchClass = "safe"
	SwitchRisky   SwitchClass = "risky"
	SwitchNever   SwitchClass = "never"
	SwitchUnknown SwitchClass = "unknown"
)

// SwitchPolicy is the built-in table.
type SwitchPolicy struct {
	Class SwitchClass
	Why   string
}

// FeaturePolicy is the classification for this firmware family.
var FeaturePolicy = map[string]SwitchPolicy{
	// --- safe to enable -------------------------------------------------------
	"SYS_ADB_SWITCH": {
		SwitchSafe, "adbd over USB; useful for debugging, no network exposure"},
	"USR_DDNS_SW": {
		SwitchSafe, "shows/enables the DDNS page; inert until a provider is configured"},
	"USR_NW_AIRPLANE_MODE_ENABLE": {
		SwitchSafe, "exposes airplane mode in the UI"},
	"USR_DATA_ROAMING_SW": {
		SwitchSafe, "allows data while roaming; only costs money away from the home PLMN"},
	"SYS_TELNET_SWITCH": {
		SwitchRisky, "the vendor's own telnet on 9876. It has a real login handler, but it is " +
			"plaintext and the shipped password is admin/admin - a second guessable service"},
	"USR_IDU_TELNET_SWITCH": {
		SwitchRisky, "same vendor telnet path, IDU-side gate"},

	// --- works, but not free --------------------------------------------------
	// NOT UPnP. This is the master firewall switch, and it is load-bearing twice
	// over: /etc/tzscript/iptables_config only executes the generated
	// /tmp/cmdlib/iptables/iptables_dmz_function when USR_FWT_SW != 0. Turning it
	// off disables packet filtering AND silently stops the saved DMZ payload from
	// replaying at boot, i.e. it removes the root console.
	"USR_FWT_SW": {
		SwitchNever, "master firewall switch. iptables_config only runs the generated " +
			"iptables_dmz_function when this is non-zero, so turning it off both disables " +
			"packet filtering and stops the saved DMZ payload from replaying at boot"},
	"USR_FWT_UPNP_SW": {
		SwitchRisky, "UPnP/IGD: same, and it advertises the router on the LAN"},
	"SYS_MDL_LOG_SW": {
		SwitchRisky, "modem logging: continuous writes to the same ubifs volume as /etc"},
	"USR_APN_SW_1": {
		SwitchRisky, "extra PDP profile slot; inert until an APN is typed into it, but the active profile set is re-read on apply"},
	"USR_APN_SW_2": {
		SwitchRisky, "extra PDP profile slot; same"},
	"USR_APN_SW_3": {
		SwitchRisky, "extra PDP profile slot; same"},
	"SYS_SN_FIXED_SW": {
		SwitchRisky, "pins the serial number; leave alone unless the SN is actually wrong"},

	// --- never turn these ON --------------------------------------------------
	"SYS_LOCK_SIM_SW": {
		SwitchNever, "enabling it locks the SIM behind a PIN - the opposite of enabling the device"},
	"SYS_LOCK_PHONE_SW": {
		SwitchNever, "enabling it locks the handset"},
	"SYS_LOCK_OPERATOR_SW": {
		SwitchNever, "enabling it restricts the device to one operator's PLMN"},
	"USR_TR069_CPE_AUTH_SW": {
		SwitchNever, "TR-069: gives the operator's ACS an authenticated management channel"},
	"USR_TR069_LONG_CONNECT_ENABLE": {
		SwitchNever, "TR-069: keeps a permanent management session to the ACS"},
	"USR_TR069_UPGRADE_AUTO_SW": {
		SwitchNever, "TR-069: lets the ACS push firmware to this device"},
	"SYS_TR069_UPGRADE_PROMPT_SW": {
		SwitchNever, "TR-069: operator-initiated upgrade prompts"},
	"USR_ENABLE_WEB_LOGIN_IP_FROM_WAN_SW": {
		SwitchNever, "publishes the web UI on the WAN - this is how these units get owned remotely"},
	"USR_ENABLE_WEB_LOGIN_IP_FROM_LAN_SW": {
		SwitchNever, "IP-allowlists LAN web logins; enabling can lock you out"},
	"REMOTE_LOGIN_ENABLE": {
		SwitchNever, "remote login path; the WAN firewall is the only thing holding it shut"},
}

// FeatureSwitch is one config key and its state.
type FeatureSwitch struct {
	Key   string
	Value string
	Class SwitchClass
	Why   string
	// Setting reports whether it currently looks OFF.
	Off bool
}

// String renders one row.
func (f FeatureSwitch) String() string {
	state := "on "
	if f.Off {
		state = "OFF"
	}
	return fmt.Sprintf("%-38s %s  %-7s %s", f.Key, state, f.Class, f.Why)
}

// Features reads the switch inventory over the root shell.
type Features struct {
	Shell *Shell
}

// switchKeysList is a portable way to name the candidate keys without depending
// on grep -o (busybox grep in this image is fine, but the config format varies).
func (f *Features) read(key string) (string, error) {
	out, code, err := f.Shell.Run(fmt.Sprintf("mdlcfg -g %s", key))
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", nil // unknown key
	}
	v := strings.TrimSpace(out)
	v = strings.Trim(v, `"`)
	return v, nil
}

// List returns the known keys with their live values, sorted: OFF first, then by
// class severity.
func (f *Features) List() ([]FeatureSwitch, error) {
	var out []FeatureSwitch
	for key, pol := range FeaturePolicy {
		v, err := f.read(key)
		if err != nil {
			return nil, err
		}
		if v == "" {
			continue // not present on this firmware/SKU
		}
		out = append(out, FeatureSwitch{
			Key: key, Value: v, Class: pol.Class, Why: pol.Why,
			Off: v == "0" || strings.EqualFold(v, "off") || strings.EqualFold(v, "no"),
		})
	}
	rank := func(c SwitchClass) int {
		switch c {
		case SwitchNever:
			return 0
		case SwitchRisky:
			return 1
		case SwitchSafe:
			return 2
		default:
			return 3
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Off != out[j].Off {
			return out[i].Off // OFF first
		}
		if rank(out[i].Class) != rank(out[j].Class) {
			return rank(out[i].Class) < rank(out[j].Class)
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// Set writes one switch. `never` keys are refused in the enabling direction.
func (f *Features) Set(key string, on bool) error {
	pol, known := FeaturePolicy[key]
	if !known {
		return fmt.Errorf("zlt: %s is not in the policy table; refusing to change an unclassified switch", key)
	}
	if on && pol.Class == SwitchNever {
		return fmt.Errorf("zlt: refusing to enable %s: %s", key, pol.Why)
	}
	val := "0"
	if on {
		val = "1"
	}
	out, code, err := f.Shell.Run(fmt.Sprintf("mdlcfg -a %s=%s", key, val))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("zlt: mdlcfg -a %s failed (exit %d): %s", key, code, strings.TrimSpace(out))
	}
	// Read back; a silent no-op is the normal failure mode here.
	got, err := f.read(key)
	if err != nil {
		return err
	}
	if got != val {
		return fmt.Errorf("zlt: %s did not take (wanted %s, device says %q)", key, val, got)
	}
	return nil
}

// Persist saves the parameter set to flash (mdlcfg -c).
func (f *Features) Persist() error {
	out, code, err := f.Shell.Run("mdlcfg -c")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("zlt: mdlcfg -c failed (exit %d): %s", code, strings.TrimSpace(out))
	}
	return nil
}

// ApplyClass enables every OFF switch of the given class. `never` is rejected by
// construction - there is no code path that enables one.
func (f *Features) ApplyClass(class SwitchClass) ([]string, error) {
	if class == SwitchNever {
		return nil, fmt.Errorf("zlt: refusing to apply the never class")
	}
	list, err := f.List()
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, s := range list {
		if !s.Off || s.Class != class {
			continue
		}
		if err := f.Set(s.Key, true); err != nil {
			return changed, err
		}
		changed = append(changed, s.Key)
	}
	if len(changed) > 0 {
		if err := f.Persist(); err != nil {
			return changed, err
		}
	}
	return changed, nil
}
