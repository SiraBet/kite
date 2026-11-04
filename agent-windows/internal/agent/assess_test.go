package agent

import (
	"errors"
	"strings"
	"testing"
)

// The distinction these tests protect: a search that did not run must
// never look like a host with nothing pending. Everything else about the
// assessment is detail; this is the part that, if it regresses, makes an
// unpatched fleet report as clean.
func TestParseAssessmentDistinguishesFailureFromNothingPending(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		runErr  error
		wantOK  bool
		wantLen int
		wantErr string // substring the reason must contain
	}{
		{
			name:    "script never started",
			out:     "",
			runErr:  errors.New(`exec: "powershell.exe": not found`),
			wantOK:  false,
			wantErr: "could not run",
		},
		{
			name:    "script ran but printed nothing usable",
			out:     "Windows PowerShell\nCopyright (C) Microsoft Corporation.",
			wantOK:  false,
			wantErr: "returned no result",
		},
		{
			name:    "script printed malformed JSON",
			out:     `{"ok": true, "updates": [`,
			wantOK:  false,
			wantErr: "could not read",
		},
		{
			name:    "search itself failed on the host",
			out:     `{"ok":false,"error":"WSUS server unreachable (0x80244022)","updates":[]}`,
			wantOK:  false,
			wantErr: "WSUS",
		},
		{
			name:   "host genuinely has nothing pending",
			out:    `{"ok":true,"error":"","updates":[]}`,
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			updates, ok, reason := parseAssessment(tc.out, tc.runErr)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (reason %q)", ok, tc.wantOK, reason)
			}
			if len(updates) != tc.wantLen {
				t.Errorf("got %d updates, want %d", len(updates), tc.wantLen)
			}
			if tc.wantErr != "" && !strings.Contains(reason, tc.wantErr) {
				t.Errorf("reason %q does not mention %q", reason, tc.wantErr)
			}
			if tc.wantOK && reason != "" {
				t.Errorf("a successful assessment carried a reason: %q", reason)
			}
		})
	}
}

func TestParseAssessmentReadsUpdates(t *testing.T) {
	// One line, because search.ps1 emits ConvertTo-Json -Compress and
	// lastJSONLine reads a single line. Pretty-printed JSON would not
	// survive the trip, which is why the script compresses it.
	out := `{"ok":true,"error":"","updates":[` +
		`{"package":"2024-11 Cumulative Update (KB5046617)","new_version":"KB5046617","advisory":"KB5046617","severity":"critical","is_security":true},` +
		`{"package":"Intel driver update","new_version":"","advisory":"","severity":"unknown","is_security":false}]}`
	updates, ok, reason := parseAssessment(out, nil)
	if !ok || reason != "" {
		t.Fatalf("ok=%v reason=%q", ok, reason)
	}
	if len(updates) != 2 {
		t.Fatalf("got %d updates, want 2", len(updates))
	}
	if updates[0].Severity != "critical" || !updates[0].IsSecurity {
		t.Errorf("first update lost its severity: %+v", updates[0])
	}
	// An update Windows publishes no severity for stays 'unknown' rather
	// than being graded down to 'low' -- the controller ranks it as
	// unassessed, which is the honest answer.
	if updates[1].Severity != "unknown" {
		t.Errorf("second update severity = %q, want unknown", updates[1].Severity)
	}
}

func TestLastJSONLineSkipsPrecedingNoise(t *testing.T) {
	out := "profile banner\nWARNING: something\n{\"ok\":true}\n"
	if got := lastJSONLine(out); got != `{"ok":true}` {
		t.Errorf("lastJSONLine = %q", got)
	}
	if got := lastJSONLine("no json here\n"); got != "" {
		t.Errorf("lastJSONLine on plain text = %q, want empty", got)
	}
	// Windows line endings: the \r must not end up inside the JSON.
	if got := lastJSONLine("noise\r\n{\"ok\":false}\r\n"); got != `{"ok":false}` {
		t.Errorf("lastJSONLine with CRLF = %q", got)
	}
}

// truncate keeps the END of the output, not the start: when a four-hour
// patch run is cut down to fit, the useful part is the failure it ended
// on, not the banner it opened with.
func TestTruncateKeepsTheTail(t *testing.T) {
	if got := truncate("abcdefghij", 4); got != "ghij" {
		t.Errorf("truncate = %q, want %q", got, "ghij")
	}
	if got := truncate("short", 40); got != "short" {
		t.Errorf("truncate shortened something already short: %q", got)
	}
}

// winget.ps1 emits the same JSON envelope shape as search.ps1, plus a
// `present` flag. parseWingetAssessment must keep "winget is not here"
// (present=false) distinct from "winget ran and found nothing" and from
// "winget broke" -- the controller treats all three differently.
func TestParseWingetAssessment(t *testing.T) {
	cases := []struct {
		name        string
		out         string
		runErr      error
		wantPresent bool
		wantOK      bool
		wantCount   int
	}{
		{
			name:        "winget absent",
			out:         `{"present":false,"ok":false,"error":"winget (App Installer) is not installed","updates":[]}`,
			wantPresent: false, wantOK: false, wantCount: 0,
		},
		{
			name:        "present, nothing upgradable",
			out:         `{"present":true,"ok":true,"error":"","updates":[]}`,
			wantPresent: true, wantOK: true, wantCount: 0,
		},
		{
			name: "present with upgrades",
			out: `{"present":true,"ok":true,"error":"","updates":[` +
				`{"package":"Google Chrome","new_version":"117.0","current_version":"116.0","advisory":"Google.Chrome","severity":"none","is_security":false}]}`,
			wantPresent: true, wantOK: true, wantCount: 1,
		},
		{
			name:        "present but failed",
			out:         `{"present":true,"ok":false,"error":"winget exited 1","updates":[]}`,
			wantPresent: true, wantOK: false, wantCount: 0,
		},
		{
			name:        "powershell produced nothing",
			out:         "",
			runErr:      errors.New("powershell not found"),
			wantPresent: true, wantOK: false, wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			updates, present, ok, reason := parseWingetAssessment(tc.out, tc.runErr)
			if present != tc.wantPresent || ok != tc.wantOK || len(updates) != tc.wantCount {
				t.Fatalf("present=%v ok=%v n=%d reason=%q; want present=%v ok=%v n=%d",
					present, ok, len(updates), reason, tc.wantPresent, tc.wantOK, tc.wantCount)
			}
			if tc.wantCount == 1 {
				u := updates[0]
				if u.CurrentVersion != "116.0" || u.NewVersion != "117.0" || u.Advisory != "Google.Chrome" {
					t.Errorf("parsed update = %+v", u)
				}
			}
		})
	}
}
