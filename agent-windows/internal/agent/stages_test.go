package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestStageExcludesRecordsPatterns(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	agent := &Agent{cfg: &Config{}}
	in := &Instruction{Excludes: []map[string]any{
		{"pkg_pattern": "KB5046617", "mode": "skip"},
		{"pkg_pattern": "*Silverlight*", "mode": "pin"},
		{"pkg_pattern": "KB5046617", "mode": "skip"}, // duplicate
		{"pkg_pattern": ""},                          // empty
	}}
	status, output := agent.stageExcludes(in)
	if status != "done" {
		t.Fatalf("status = %q, output = %q", status, output)
	}

	raw, err := os.ReadFile(excludesPath())
	if err != nil {
		t.Fatal(err)
	}
	var patterns []string
	if err := json.Unmarshal(raw, &patterns); err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 || patterns[0] != "KB5046617" || patterns[1] != "*Silverlight*" {
		t.Errorf("patterns = %v, want the two distinct non-empty ones in order", patterns)
	}
	// Windows Update cannot hold a package at a version, so a pin is
	// recorded as a skip. The stage output has to say so plainly rather
	// than implying a pin was honoured.
	if !strings.Contains(output, "*Silverlight*") {
		t.Errorf("output does not list what was applied: %q", output)
	}
}

func TestStageExcludesWithNoRules(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	agent := &Agent{cfg: &Config{}}
	status, output := agent.stageExcludes(&Instruction{})
	if status != "done" {
		t.Fatalf("status = %q", status)
	}
	if !strings.Contains(output, "no exclude rules") {
		t.Errorf("output = %q", output)
	}
	// The file is still written: stagePatch reads it unconditionally, and
	// a stale file from a previous run would otherwise keep applying
	// excludes this run deliberately cleared.
	raw, err := os.ReadFile(excludesPath())
	if err != nil {
		t.Fatalf("excludes file was not written: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "null" && strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("excludes file = %q, want an empty list", raw)
	}
}

// An unknown stage is a controller/agent version mismatch. Failing it
// with a reason is right; returning "done" would let a job walk past a
// stage that never ran.
func TestExecuteRejectsUnknownStage(t *testing.T) {
	agent := &Agent{cfg: &Config{}}
	status, output := agent.execute(&Instruction{StageName: "quantum-defrag"})
	if status != "failed" {
		t.Fatalf("status = %q", status)
	}
	if !strings.Contains(output, "quantum-defrag") {
		t.Errorf("output does not name the stage: %q", output)
	}
}

// Windows hosts run no containers kite can update. Saying so is the
// point: a silent "done" would report a container update that never
// happened.
func TestExecuteRefusesContainerStage(t *testing.T) {
	agent := &Agent{cfg: &Config{}}
	status, output := agent.execute(&Instruction{StageName: "containers",
		Containers: []map[string]any{{"name": "web"}}})
	if status != "failed" || !strings.Contains(output, "container") {
		t.Errorf("status = %q, output = %q", status, output)
	}
}

func TestResumePendingRebootIgnoresJunkState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	if err := os.WriteFile(StatePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No controller configured: this must not panic or block, and it
	// must clear the unusable file rather than retrying it forever.
	agent := &Agent{cfg: &Config{}, client: NewClient(&Config{ControllerURL: "http://127.0.0.1:1", VerifyTLS: true})}
	agent.ResumePendingReboot()
	if _, err := os.Stat(StatePath()); !os.IsNotExist(err) {
		t.Error("an unreadable pending-reboot file was left in place")
	}
}

func TestStatusHolderSnapshotIsACopy(t *testing.T) {
	holder := &StatusHolder{}
	holder.set(func(s *Status) { s.CurrentJob, s.CurrentStage = 5, "patch" })
	snapshot := holder.snapshot()
	holder.set(func(s *Status) { s.CurrentJob, s.CurrentStage = 0, "" })
	if snapshot.CurrentJob != 5 || snapshot.CurrentStage != "patch" {
		t.Errorf("snapshot changed under the caller: %+v", snapshot)
	}
}

func TestStatusHolderIsConcurrencySafe(t *testing.T) {
	holder := &StatusHolder{}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			holder.set(func(s *Status) { s.PendingCount++ })
		}
		close(done)
	}()
	for i := 0; i < 500; i++ {
		_ = holder.snapshot()
	}
	<-done
	if got := holder.snapshot().PendingCount; got != 500 {
		t.Errorf("PendingCount = %d, want 500", got)
	}
}

// An OS-scope run walks the containers stage on every host, including
// Windows hosts that have none. An empty selection is a completed stage,
// not a failure -- treating it as a failure would fail every OS patch
// run on a host with no containers, right after the patch itself
// succeeded.
func TestContainersStageEmptyIsDone(t *testing.T) {
	a := &Agent{}
	status, out := a.execute(&Instruction{StageName: "containers", Containers: nil})
	if status != "done" {
		t.Fatalf("empty containers stage: got %q (%s), want done", status, out)
	}
	status, _ = a.execute(&Instruction{StageName: "containers",
		Containers: []map[string]any{{"name": "x"}}})
	if status != "failed" {
		t.Fatalf("non-empty containers stage on windows agent: got %q, want failed", status)
	}
}

// A lost report makes the controller hand the same stage out again: the
// agent sends the result it already has instead of running it twice.
func TestAStageHandedOutAgainResendsItsReport(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	var reports []string
	client, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		reports = append(reports, r.URL.Path+" "+string(raw))
		fmt.Fprint(w, `{"ok": true}`)
	})
	defer srv.Close()
	agent := &Agent{cfg: &Config{}, client: client}
	in := &Instruction{JobID: 5, StageName: "excludes", Excludes: []map[string]any{{"pkg_pattern": "KB1", "mode": "skip"}}}

	agent.RunStage(in)
	if err := os.Remove(excludesPath()); err != nil {
		t.Fatal(err)
	}
	agent.RunStage(in)
	if _, err := os.Stat(excludesPath()); !os.IsNotExist(err) {
		t.Error("the stage ran a second time")
	}
	if len(reports) != 2 || reports[0] != reports[1] || !strings.Contains(reports[0], "/jobs/5/stages/excludes/report") {
		t.Errorf("reports = %q, want the same report twice", reports)
	}
	agent.RunStage(&Instruction{JobID: 6, StageName: "excludes"}) // another run's stage runs as usual
	if _, err := os.Stat(excludesPath()); err != nil {
		t.Error("another run's stage didn't run")
	}
}

// The patch stage uses the run's own rules: excludes.json is only what
// the built-in excludes stage last wrote, and a custom excludes script
// never rewrites it.
func TestPatchUsesTheRunsRulesNotAStaleFile(t *testing.T) {
	in := &Instruction{Excludes: []map[string]any{
		{"pkg_pattern": "KB1", "mode": "skip"}, {"pkg_pattern": "KB1", "mode": "skip"}, {"pkg_pattern": "*Preview*"}}}
	if got := fmt.Sprint(excludePatterns(in)); got != "[KB1 *Preview*]" {
		t.Errorf("patterns = %s", got)
	}
}

// Windows Update is asked for software it offers by itself -- no drivers,
// no optional/preview updates -- and a partial install fails the stage
// with each update's own result, rather than listing everything as installed.
func TestInstallScriptRules(t *testing.T) {
	for _, name := range []string{"install.ps1", "search.ps1"} {
		raw, _ := scripts.ReadFile("scripts/" + name)
		if !strings.Contains(string(raw), "Type='Software' and BrowseOnly=0") {
			t.Errorf("%s doesn't restrict the search to offered software updates", name)
		}
	}
	raw, _ := scripts.ReadFile("scripts/install.ps1")
	for _, rule := range []string{"GetUpdateResult($i)", "installed with errors:", "$install.ResultCode -ne 2 -or $failed -gt 0"} {
		if !strings.Contains(string(raw), rule) {
			t.Errorf("install.ps1 lost the rule containing %q", rule)
		}
	}
	if _, err := scripts.ReadFile("scripts/smbios.ps1"); err != nil {
		t.Error("smbios.ps1 isn't embedded")
	}
}
