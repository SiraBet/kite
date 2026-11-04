package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionNewerOnlyGoesUp(t *testing.T) {
	cases := []struct {
		want, have string
		newer      bool
	}{
		{"0.5.0", "0.4.0", true},
		{"0.10.0", "0.9.9", true}, // numbers, not strings
		{"0.4.0", "0.4.0", false},
		{"0.3.9", "0.4.0", false}, // never down
		{"1.0", "0.9.9", true},
		{"0.4.0.1", "0.4.0", true},
		{"", "0.4.0", false},
		{"0.5.0; del *", "0.4.0", false}, // malformed never triggers a download
	}
	for _, c := range cases {
		if got := versionNewer(c.want, c.have); got != c.newer {
			t.Errorf("versionNewer(%q, %q) = %v, want %v", c.want, c.have, got, c.newer)
		}
	}
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestCheckAgentBuildTrustsOnlyAMatchingDownload(t *testing.T) {
	data := []byte("MZ...new agent")
	if _, err := checkAgentBuild(data, sum(data), "0.5.0", "0.5.0"); err != nil {
		t.Fatalf("a matching build was refused: %v", err)
	}
	for name, args := range map[string][3]string{
		"wrong checksum": {sum([]byte("other")), "0.5.0", "0.5.0"},
		"wrong version":  {sum(data), "0.4.0", "0.5.0"},
		"no checksum":    {"", "0.5.0", "0.5.0"},
		"no version":     {sum(data), "", "0.5.0"},
	} {
		if _, err := checkAgentBuild(data, args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFetchAgentBuildReadsTheControllersHeaders(t *testing.T) {
	data := []byte("MZ...0.5.0")
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/download/agent/windows" {
			t.Errorf("fetched %s", r.URL.Path)
		}
		w.Header().Set("X-Kite-Sha256", sum(data))
		w.Header().Set("X-Kite-Agent-Version", "0.5.0")
		w.Write(data)
	})
	build, err := client.fetchAgentBuild("0.5.0")
	if err != nil || string(build.data) != string(data) {
		t.Fatalf("build=%v err=%v", build, err)
	}
}

func TestSwapBinaryKeepsTheOldOneAsideAndRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	current, staged := filepath.Join(dir, "kite-agent.exe"), filepath.Join(dir, "kite-agent.exe.new")
	os.WriteFile(current, []byte("old"), 0o755)
	os.WriteFile(staged, []byte("new"), 0o755)
	if err := swapBinary(current, staged); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Errorf("current = %q", got)
	}
	if got, _ := os.ReadFile(current + ".old"); string(got) != "old" {
		t.Errorf(".old = %q", got)
	}
	// staged missing: the running binary must be put back
	if err := swapBinary(current, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("swap with nothing staged succeeded")
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Errorf("after a failed swap current = %q, want it restored", got)
	}
}

func TestSelfUpdateIsNotAttemptedOutsideTheServiceOrForOlderVersions(t *testing.T) {
	calls := 0
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	a := &Agent{cfg: &Config{}, client: client}
	if a.maybeSelfUpdate("0.0.1") || a.maybeSelfUpdate("99.0.0") { // older; and not a service here
		t.Fatal("reported an update")
	}
	if calls != 0 {
		t.Errorf("downloaded %d times", calls)
	}
}

// A new binary keeps the previous one as a way back until it has reached
// the controller; one that keeps starting without getting there is
// replaced by the previous one.
func TestABadUpdateGoesBackToThePreviousAgent(t *testing.T) {
	t.Setenv("KITE_PROGRAM_DIR", t.TempDir())
	exe := AgentExePath()
	os.WriteFile(exe, []byte("new"), 0o755)
	os.WriteFile(exe+".old", []byte("previous"), 0o755)
	for i := 1; i <= maxUntriedStarts; i++ {
		if checkNewBinary() {
			t.Fatalf("rolled back on start %d", i)
		}
	}
	if !checkNewBinary() {
		t.Fatal("still on the bad agent after too many starts")
	}
	if got, _ := os.ReadFile(exe); string(got) != "previous" {
		t.Errorf("running binary = %q, want the previous one back", got)
	}
	if _, err := os.Stat(exe + ".old"); !os.IsNotExist(err) {
		t.Error(".old still there")
	}
	if checkNewBinary() {
		t.Error("rolled back again with nothing to go back to")
	}
}

func TestReachingTheControllerKeepsTheNewAgent(t *testing.T) {
	t.Setenv("KITE_PROGRAM_DIR", t.TempDir())
	exe := AgentExePath()
	os.WriteFile(exe, []byte("new"), 0o755)
	os.WriteFile(exe+".old", []byte("previous"), 0o755)
	checkNewBinary()
	newBinaryHealthy()
	for i := 0; i < maxUntriedStarts+2; i++ {
		if checkNewBinary() {
			t.Fatal("rolled back an agent that had reached the controller")
		}
	}
	if got, _ := os.ReadFile(exe); string(got) != "new" {
		t.Errorf("running binary = %q", got)
	}
}
