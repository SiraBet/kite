package agent

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The stage scripts ship inside the binary, so the download is one file
// with nothing to unpack and nothing that can go missing on the host.
//
//go:embed scripts/*.ps1
var scripts embed.FS

// runCtx is the parent of every PowerShell process a stage starts.
// StopRunningWork cancels it when the service is told to stop, so a
// script in progress is ended with the service rather than left running
// orphaned, its stage never reported.
var runCtx, stopRunning = context.WithCancel(context.Background())

func StopRunningWork() { stopRunning() }

// stoppedNote says why a stage ended early, when it did because the
// service was stopping.
func stoppedNote() string {
	if runCtx.Err() != nil {
		return "stopped: the kite agent service was stopped while this ran"
	}
	return ""
}

// PowerShell drives the Windows Update COM API. Not PSWindowsUpdate: that
// module must be installed from PSGallery first, which needs internet
// access on a host that may deliberately have none, and turns "assess
// this machine" into "install software on this machine". The COM API is
// present on every supported Windows version.
func runScript(name string, timeout time.Duration, args ...string) (string, error) {
	body, err := scripts.ReadFile("scripts/" + name)
	if err != nil {
		return "", fmt.Errorf("embedded script %s missing: %w", name, err)
	}
	// Written out rather than piped to -Command: a script file keeps
	// param() blocks, quoting and multi-line syntax behaving normally.
	dir, err := os.MkdirTemp("", "kite")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(runCtx, timeout)
	defer cancel()
	full := append([]string{
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path,
	}, args...)
	cmd := exec.CommandContext(ctx, powershellExe(), full...)
	// Killing PowerShell at the timeout doesn't end what it started; a
	// child left holding the output pipe would keep CombinedOutput waiting
	// forever, and the agent with it -- no more polls, no more reports.
	// WaitDelay bounds that wait after the kill.
	cmd.WaitDelay = 15 * time.Second
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if note := stoppedNote(); note != "" {
		return text, fmt.Errorf("%s %s", name, note)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return text, err
}

// powershellExe prefers Windows PowerShell, which is present on every
// Windows host. PowerShell 7 is an optional install and cannot be
// assumed; the COM calls these scripts make work on both.
func powershellExe() string {
	if path, err := exec.LookPath("powershell.exe"); err == nil {
		return path
	}
	if path, err := exec.LookPath("pwsh"); err == nil {
		return path
	}
	return "powershell.exe"
}

// PendingUpdate mirrors the controller's schema for reported updates.
type PendingUpdate struct {
	Package    string `json:"package"`
	NewVersion string `json:"new_version"`
	Advisory   string `json:"advisory"`
	Severity   string `json:"severity"`
	IsSecurity bool   `json:"is_security"`
	// Which manager found this. "os" is Windows Update; "winget" is a
	// third-party app like Chrome or Notepad++. See the controller's
	// models.PendingUpdate.source.
	Source string `json:"source"`
	// The version installed now, where the source reports one. Windows
	// Update gives only the KB (the target), so this is blank for "os";
	// winget reports both, which is what lets the console show a
	// current -> available comparison.
	CurrentVersion string `json:"current_version"`
}

// SourceStatus is one manager's assessment result. The agent attempts
// every manager the host actually has and reports, per manager, whether
// the query ran -- so the controller can refresh one source without
// blanking another it could not re-check this round.
type SourceStatus struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type assessment struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error"`
	Updates []PendingUpdate `json:"updates"`
}

// AssessUpdates reports what is pending, and separately whether the
// question could be answered at all. A search that failed is not a host
// with nothing outstanding: an unreachable WSUS would otherwise show a
// machine as fully patched while it carries every update it ever missed.
func AssessUpdates() ([]PendingUpdate, bool, string) {
	out, err := runScript("search.ps1", 10*time.Minute)
	return parseAssessment(out, err)
}

// wingetAssessment is winget.ps1's envelope. Present is false on a host
// with no winget (App Installer), which is not a failure -- there is
// simply nothing for winget to manage, and reporting a phantom failing
// source there would be a permanent false alarm.
type wingetAssessment struct {
	Present bool            `json:"present"`
	OK      bool            `json:"ok"`
	Error   string          `json:"error"`
	Updates []PendingUpdate `json:"updates"`
}

// assessWinget reports third-party apps with an available upgrade, via
// the Windows Package Manager. Returns (updates, present, ok, error):
// present says whether winget exists at all, ok whether the query
// succeeded when it does.
func assessWinget() ([]PendingUpdate, bool, bool, string) {
	out, err := runScript("winget.ps1", 5*time.Minute)
	return parseWingetAssessment(out, err)
}

func parseWingetAssessment(out string, runErr error) ([]PendingUpdate, bool, bool, string) {
	if runErr != nil && out == "" {
		return nil, true, false, fmt.Sprintf("winget assessment could not run: %v", runErr)
	}
	line := lastJSONLine(out)
	if line == "" {
		return nil, true, false, "winget assessment returned no result: " + truncate(out, 300)
	}
	var res wingetAssessment
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		return nil, true, false, "could not read the winget result: " + truncate(out, 300)
	}
	return res.Updates, res.Present, res.OK, res.Error
}

// AssessAll runs every update source this host has and returns the merged
// findings plus a per-source status. Each finding is tagged with the
// source that produced it, so the controller can refresh sources
// independently. The OS source is always attempted; winget only when it
// is present.
func AssessAll() ([]PendingUpdate, []SourceStatus) {
	var all []PendingUpdate
	var sources []SourceStatus

	osUpdates, osOK, osErr := AssessUpdates()
	for i := range osUpdates {
		osUpdates[i].Source = "os"
	}
	all = append(all, osUpdates...)
	sources = append(sources, SourceStatus{Name: "os", OK: osOK, Error: osErr})

	wUpdates, present, wOK, wErr := assessWinget()
	if present {
		for i := range wUpdates {
			wUpdates[i].Source = "winget"
		}
		all = append(all, wUpdates...)
		sources = append(sources, SourceStatus{Name: "winget", OK: wOK, Error: wErr})
	}
	return all, sources
}

// parseAssessment turns what search.ps1 printed into the three values the
// controller needs. Every failure path returns ok=false with a reason
// rather than an empty update list: "the search did not run" and "this
// host has nothing outstanding" are different answers, and reporting the
// first as the second is how an unpatched fleet looks healthy.
func parseAssessment(out string, runErr error) ([]PendingUpdate, bool, string) {
	if runErr != nil && out == "" {
		return nil, false, fmt.Sprintf("update search could not run: %v", runErr)
	}
	// The script emits one JSON object as its last line; anything before
	// it is noise from the host's profile or a transcript.
	line := lastJSONLine(out)
	if line == "" {
		return nil, false, "update search returned no result: " + truncate(out, 300)
	}
	var result assessment
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		return nil, false, "could not read the update search result: " + truncate(out, 300)
	}
	return result.Updates, result.OK, result.Error
}

func lastJSONLine(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "{") {
			return trimmed
		}
	}
	return ""
}
