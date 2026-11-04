package agent

import (
	"strings"
	"testing"
)

func envMap(t *testing.T, in *Instruction) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, kv := range customScriptEnv(in) {
		parts := strings.SplitN(kv, "=", 2)
		m[parts[0]] = parts[1]
	}
	return m
}

// The whole point of the env contract: a custom patch script must be able to
// see the scope the operator chose, or it silently patches more than asked.
func TestCustomScriptEnvCarriesTheSeverityScope(t *testing.T) {
	env := envMap(t, &Instruction{
		JobID: 42, StageName: "patch", Hostname: "win-01",
		SeverityFilter: "Critical,Important",
	})
	if env["KITE_SEVERITY"] != "Critical,Important" {
		t.Fatalf("KITE_SEVERITY = %q", env["KITE_SEVERITY"])
	}
	if env["KITE_JOB_ID"] != "42" || env["KITE_STAGE"] != "patch" {
		t.Fatalf("job/stage wrong: %v", env)
	}
	if env["KITE_HOSTNAME"] != "win-01" {
		t.Fatalf("KITE_HOSTNAME = %q", env["KITE_HOSTNAME"])
	}
}

func TestCustomScriptEnvSplitsSkipsFromPins(t *testing.T) {
	env := envMap(t, &Instruction{
		JobID: 1, StageName: "excludes",
		Excludes: []map[string]any{
			{"pkg_pattern": "KB5001234", "mode": "skip"},
			{"pkg_pattern": "Defender*", "mode": "pin", "version": "1.2"},
			{"pkg_pattern": "", "mode": "skip"}, // ignored, not an empty entry
		},
	})
	if env["KITE_EXCLUDES"] != "KB5001234" {
		t.Fatalf("KITE_EXCLUDES = %q", env["KITE_EXCLUDES"])
	}
	if env["KITE_PINS"] != "Defender*=1.2" {
		t.Fatalf("KITE_PINS = %q", env["KITE_PINS"])
	}
}

// StageName is controller-supplied and becomes a filename, so a traversal
// attempt must be refused rather than written wherever it points.
func TestCustomScriptRefusesAnUnsafeStageName(t *testing.T) {
	for _, name := range []string{`../../evil`, `..\evil`, `C:\evil`, "..", "", "sub/dir"} {
		a := &Agent{}
		status, out := a.runCustomScript(&Instruction{
			JobID: 1, StageName: name, CustomScript: "Write-Output hi",
		})
		if status != "failed" || !strings.Contains(out, "unsafe stage name") {
			t.Fatalf("stage %q: got status=%q out=%q", name, status, out)
		}
	}
}

func TestTailRunesCutsOnARuneBoundary(t *testing.T) {
	// 5 multi-byte runes; keeping 3 must not split one into invalid bytes.
	got := tailRunes("äöüßé", 3)
	if got != "üßé" {
		t.Fatalf("tailRunes = %q", got)
	}
	if !strings.ContainsRune(got, 'é') {
		t.Fatalf("lost the final rune: %q", got)
	}
	if tailRunes("short", 50) != "short" {
		t.Fatal("truncated a string already under the limit")
	}
}
