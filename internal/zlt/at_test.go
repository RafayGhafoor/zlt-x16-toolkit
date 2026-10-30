package zlt

import (
	"strings"
	"testing"
)

// The guard is the whole safety story for the AT surface, so pin every class.
func TestClassifyAT(t *testing.T) {
	cases := []struct {
		cmd       string
		allow     bool
		forbidden bool
		optIn     bool
		why       string
	}{
		// Reads are always fine.
		{"AT+CGSN", false, false, false, "IMEI read"},
		{"AT+SIMEI?", false, false, false, "IMEI read, query form"},
		{"AT+CSQ", false, false, false, "signal"},
		{"AT+CICCID", false, false, false, "ICCID"},
		{"AT+CNVR=2497,0", false, false, false, "NV read by number"},

		// Identity / NV writes are refused outright, with or without -write.
		{"AT+SIMEI=0,\"123456789012345\"", false, true, false, "IMEI write"},
		{"AT+SIMEI=0,\"123456789012345\"", true, true, false, "IMEI write with -write"},
		{"AT+SPIMEI=0,\"123456789012345\"", true, true, false, "vendor IMEI write"},
		{"AT+CNVW=2497,0,00", true, true, false, "NV write by number"},
		{"AT+CNV=/nv/item_files/x,1,01,1", true, true, false, "NV write by path"},
		{"AT+CLCK=\"SC\",1,\"0000\"", true, true, false, "SIM lock"},
		{"AT+CPWD=\"SC\",\"0000\",\"1111\"", true, true, false, "PIN change"},
		{"AT&F", true, true, false, "factory AT reset"},
		{"AT+SFUN=2", true, true, false, "SIM function control"},

		// Known channel killers.
		{"AT+CLAC", false, true, false, "wedges the daemon"},
		{"AT+CFUN?", false, true, false, "hangs"},
		{"AT+CSYSSEL=?", false, true, false, "hangs"},

		// Policy writes need an explicit opt-in.
		{"AT+CSYSSEL=\"lte_band\",1:3", false, false, true, "band policy"},
		{"AT+CSYSSEL=\"lte_band\",1:3", true, false, false, "band policy with -write"},
		{"AT+CCELLCFG=1,120,1300", false, false, true, "cell lock"},
		{"AT+CGDCONT=1,\"IP\",\"apn\"", false, false, true, "PDP profile"},
	}
	for _, c := range cases {
		f, o, _ := ClassifyAT(c.cmd, c.allow)
		if f != c.forbidden || o != c.optIn {
			t.Errorf("%s (allow=%v): forbidden=%v optIn=%v, want forbidden=%v optIn=%v [%s]",
				c.cmd, c.allow, f, o, c.forbidden, c.optIn, c.why)
		}
	}
}

// The three reply shapes actually observed on the unit.
func TestParseATReply(t *testing.T) {
	var r ATResult
	parseATReply(&r, "atcmd_receive:\n861702085648268\n\nOK\n")
	if !r.OK || r.Single() != "861702085648268" {
		t.Fatalf("plain query: %+v", r)
	}

	r = ATResult{}
	parseATReply(&r, "atcmd_receive:\n+ICCID: 89410037251217291419\n\nOK")
	if !r.OK || r.Single() != "+ICCID: 89410037251217291419" {
		t.Fatalf("prefixed query: %+v", r)
	}

	r = ATResult{}
	parseATReply(&r, "atcmd_receive:\nERROR\n")
	if r.OK || r.Error != "ERROR" {
		t.Fatalf("error reply: %+v", r)
	}

	// atcmd's echo line must never leak into the payload.
	r = ATResult{}
	parseATReply(&r, "atcmd_receive:\n+CSQ: 31,99\n\nOK\n")
	for _, l := range r.Payload {
		if strings.Contains(l, "atcmd_receive") {
			t.Fatalf("echo leaked: %q", l)
		}
	}
}

// NV 2497 is the module serial: 15 raw bytes, hex, zero padded.
func TestHexToText(t *testing.T) {
	hexStr := "4D5030363234303335334244423043" + strings.Repeat("00", 40)
	if got := hexToText(hexStr); got != "MP06240353BDB0C" {
		t.Fatalf("hexToText = %q, want %q", got, "MP06240353BDB0C")
	}
	if got := hexToText(""); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestNVReadIsNotClassifiedAsWrite(t *testing.T) {
	// AT+CNV=<path>,0 is the read operation and must be allowed.
	if f, o, _ := ClassifyAT("AT+CNV=/nv/item_files/modem/mmode/lte_bandpref,0", false); f || o {
		t.Fatal("NV read by path must be allowed without -write")
	}
}

// Both NV reply shapes must yield the data field, not the framing.
func TestExtractNVPayload(t *testing.T) {
	byNumber := `+CNVR: 1,"4D5030363234303335334244423043000000000000"`
	if got := extractNVPayload(byNumber); got != "4D5030363234303335334244423043000000000000" {
		t.Fatalf("by number: %q", got)
	}
	if got := NVText(extractNVPayload(byNumber)); got != "MP06240353BDB0C" {
		t.Fatalf("by number text: %q", got)
	}

	byPath := "+CNV: 8,0,8,1500000820010000"
	if got := extractNVPayload(byPath); got != "1500000820010000" {
		t.Fatalf("by path: %q", got)
	}
	// Binary items must not be rendered as garbage text.
	if got := NVText(extractNVPayload(byPath)); got != "" {
		t.Fatalf("binary item decoded to junk: %q", got)
	}
}

// AT+CFUN=1,1 is allowed with -write but must warn: it resets the modem and can
// trip the dialer's AT-failure watchdog. That reboot path is documented in the
// device repo, not reproduced here.
func TestATHazardWarnsOnModemReset(t *testing.T) {
	cases := map[string]bool{
		"AT+CFUN=1,1":              true,
		"AT+CFUN=7":                true,
		"AT+CRESET":                true,
		"AT+CPOF":                  true,
		"AT+CNWSEARCH=\"lte\",120": true,
		"AT+CGSN":                  false,
		"AT+CSQ":                   false,
		"AT+CFUN=4":                false, // RF off is the safe way to do it
		"AT+CFUN?":                 false,
	}
	for cmd, wantWarn := range cases {
		got := ATHazard(cmd)
		if (got != "") != wantWarn {
			t.Errorf("ATHazard(%q) = %q, want warning=%v", cmd, got, wantWarn)
		}
	}
}
