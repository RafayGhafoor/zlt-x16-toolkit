package zlt

import (
	"strings"
	"testing"
)

// The policy table is the safety boundary. These tests pin the parts that must
// never regress: harmful switches cannot be enabled, unknown keys are refused,
// and the inventory never silently grows a class.

func TestNeverSwitchesCannotBeEnabled(t *testing.T) {
	// Set() refuses before it touches the device, so a nil shell is fine here.
	f := &Features{}
	for key, pol := range FeaturePolicy {
		if pol.Class != SwitchNever {
			continue
		}
		err := f.Set(key, true)
		if err == nil {
			t.Fatalf("%s is class never but Set(key,true) was allowed", key)
		}
		if !strings.Contains(err.Error(), "refusing to enable") {
			t.Fatalf("%s: unhelpful error %q", key, err)
		}
	}
}

func TestUnknownKeyRefused(t *testing.T) {
	f := &Features{}
	if err := f.Set("SOME_MADE_UP_SWITCH", true); err == nil {
		t.Fatal("an unclassified key must not be writable")
	}
}

func TestApplyClassNeverIsRejected(t *testing.T) {
	f := &Features{}
	if _, err := f.ApplyClass(SwitchNever); err == nil {
		t.Fatal("ApplyClass(never) must be rejected")
	}
}

// The classifications that matter most, spelled out so a refactor cannot quietly
// move one of them into `safe`.
func TestCriticalClassifications(t *testing.T) {
	mustBe := map[string]SwitchClass{
		// enabling these is the harmful direction
		"SYS_LOCK_SIM_SW":                     SwitchNever,
		"SYS_LOCK_OPERATOR_SW":                SwitchNever,
		"USR_TR069_UPGRADE_AUTO_SW":           SwitchNever,
		"USR_ENABLE_WEB_LOGIN_IP_FROM_WAN_SW": SwitchNever,
		// useful with a cost
		"USR_FWT_UPNP_SW":   SwitchRisky,
		"SYS_TELNET_SWITCH": SwitchRisky,
		"SYS_MDL_LOG_SW":    SwitchRisky,
		// no cost
		"SYS_ADB_SWITCH":              SwitchSafe,
		"USR_DDNS_SW":                 SwitchSafe,
		"USR_NW_AIRPLANE_MODE_ENABLE": SwitchSafe,
	}
	for key, want := range mustBe {
		got, ok := FeaturePolicy[key]
		if !ok {
			t.Fatalf("%s is missing from the policy table", key)
		}
		if got.Class != want {
			t.Fatalf("%s is %q, want %q", key, got.Class, want)
		}
		if strings.TrimSpace(got.Why) == "" {
			t.Fatalf("%s has no explanation", key)
		}
	}
}

func TestFeatureSwitchString(t *testing.T) {
	s := FeatureSwitch{Key: "X_SW", Value: "0", Class: SwitchSafe, Why: "because", Off: true}
	out := s.String()
	if !strings.Contains(out, "OFF") || !strings.Contains(out, "safe") || !strings.Contains(out, "because") {
		t.Fatalf("row is missing state/class/why: %q", out)
	}
}
