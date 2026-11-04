package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (a *Agent) stagePreflight() (string, string) {
	out, err := runScript("preflight.ps1", 5*time.Minute)
	if err != nil {
		return "failed", out
	}
	return "done", out
}

// stageExcludes records the skip/pin patterns for the patch stage.
//
// Windows Update cannot pin a package to a version and hold it there, so
// skip and pin are treated identically: both keep that title or KB out of
// what `patch` installs. Pretending to support pinning would be worse
// than saying it is not supported.
// excludePatterns: the run's skip/pin patterns, each once.
func excludePatterns(in *Instruction) []string {
	var patterns []string
	seen := map[string]bool{}
	for _, rule := range in.Excludes {
		pattern, _ := rule["pkg_pattern"].(string)
		if pattern != "" && !seen[pattern] {
			seen[pattern] = true
			patterns = append(patterns, pattern)
		}
	}
	return patterns
}

func (a *Agent) stageExcludes(in *Instruction) (string, string) {
	patterns := excludePatterns(in)
	raw, err := json.Marshal(patterns)
	if err != nil {
		return "failed", err.Error()
	}
	if err := os.WriteFile(excludesPath(), raw, 0o600); err != nil {
		return "failed", fmt.Sprintf("could not record exclude rules: %v", err)
	}
	if len(patterns) == 0 {
		return "done", "no exclude rules to apply"
	}
	return "done", "exclude patterns applied: " + strings.Join(patterns, ", ")
}

func excludesPath() string { return filepath.Join(InstallDir(), "excludes.json") }

func (a *Agent) stagePatch(in *Instruction) (string, string) {
	// The controller sends every stage the run's rules: these, not
	// excludes.json, which a custom excludes script never rewrites.
	patterns := excludePatterns(in)
	notes := ""
	severity := strings.TrimSpace(in.SeverityFilter)
	if severity != "" && severity != "all" && severity != "security" {
		// Windows publishes MsrcSeverity, so a severity list is honoured
		// natively here -- unlike apt, which has no severity at all.
		notes = fmt.Sprintf("restricted to severity: %s\n", severity)
	}
	out, err := runScript("install.ps1", 4*time.Hour,
		"-Exclude", strings.Join(patterns, ","), "-Severity", severity)
	if err != nil {
		return "failed", notes + out
	}
	return "done", notes + out
}

// stageReboot is the one stage that cannot return synchronously: the
// process is about to disappear. It writes the job id first, and
// ResumePendingReboot reports the stage once the host is back.
func (a *Agent) stageReboot(in *Instruction) (string, string) {
	out, err := rebootCheck()
	if err != nil {
		return "failed", "could not determine whether a reboot is needed: " + out
	}
	if !strings.Contains(strings.ToLower(out), "yes") {
		return "done", "no reboot required"
	}

	state := map[string]any{"job_id": in.JobID, "requested_at": time.Now().UTC().Format(time.RFC3339)}
	writeState := func() error {
		raw, _ := json.Marshal(state)
		return os.WriteFile(StatePath(), raw, 0o600)
	}
	if err := writeState(); err != nil {
		return "failed", fmt.Sprintf("refusing to reboot: could not record the pending job (%v). "+
			"Rebooting without this would leave job %d running forever.", err, in.JobID)
	}

	Info("reboot required for job %d -- rebooting now, will report when back", in.JobID)
	note, err := restartNow("kite: rebooting to finish patching")
	if err != nil {
		os.Remove(StatePath())
		return "failed", "reboot command failed: " + err.Error()
	}
	if note != "" {
		Info("%s", note)
		state["note"] = note
		_ = writeState() // only adds the note to what's reported once the host is back
	}
	return "deferred", ""
}

// rebootCheck asks Windows whether a restart is pending; a variable so tests can stand in for it.
var rebootCheck = func() (string, error) { return runScript("rebootcheck.ps1", 2*time.Minute) }

// Windows' ERROR_SHUTDOWN_IS_SCHEDULED: a restart or shutdown is already
// counting down -- typically Windows Update's own restart for updates it
// installed earlier.
const errShutdownIsScheduled = 1190

// runShutdown is shutdown.exe; a variable so tests can stand in for it.
var runShutdown = func(args ...string) error { return exec.Command("shutdown", args...).Run() }

// restartNow restarts the machine in a few seconds. When Windows already
// has a restart scheduled, that one is cancelled and this one issued in
// its place: the machine restarts either way, and the run is waiting on
// it now rather than whenever the scheduled one falls due. Returns a note
// saying so, for the stage's result.
//
// A machine already shutting down (error 1115) is going down anyway:
// that is the restart the run waits for, not a failure.
func restartNow(comment string) (string, error) {
	err := runShutdown("/r", "/t", "5", "/c", comment)
	if err == nil {
		return "", nil
	}
	if exitCode(err) == errShuttingDown {
		return alreadyShuttingDown, nil
	}
	if exitCode(err) != errShutdownIsScheduled {
		return "", describeShutdownError(err)
	}
	_ = runShutdown("/a") // cancel the scheduled one; if it already went, the retry says so
	if err := runShutdown("/r", "/t", "5", "/c", comment); err != nil {
		if exitCode(err) == errShuttingDown {
			return alreadyShuttingDown, nil
		}
		return "", fmt.Errorf("a restart was already scheduled on this machine, and replacing it with an immediate one failed: %w",
			describeShutdownError(err))
	}
	return "a restart was already scheduled on this machine (usually Windows Update's); kite replaced it with an immediate one", nil
}

// Windows' ERROR_SHUTDOWN_IN_PROGRESS.
const errShuttingDown = 1115

const alreadyShuttingDown = "the machine was already shutting down when kite asked it to restart"

// exitCode is the process exit code inside err (*exec.ExitError has one), or -1.
func exitCode(err error) int {
	var e interface{ ExitCode() int }
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -1
}

// describeShutdownError turns shutdown.exe's exit codes (Windows error
// numbers) into words.
func describeShutdownError(err error) error {
	switch exitCode(err) {
	case errShutdownIsScheduled:
		return fmt.Errorf("a restart or shutdown is already scheduled on this machine (error 1190)")
	case errShuttingDown:
		return fmt.Errorf("the machine is already shutting down (error 1115)")
	case 5:
		return fmt.Errorf("access denied -- the agent must run as SYSTEM or an administrator (error 5)")
	}
	return err
}

// ResumePendingReboot runs on every start. If the agent rebooted mid-job,
// this is what closes that stage out.
func (a *Agent) ResumePendingReboot() {
	raw, err := os.ReadFile(StatePath())
	if err != nil {
		return
	}
	var state struct {
		JobID int    `json:"job_id"`
		Note  string `json:"note"`
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.JobID == 0 {
		os.Remove(StatePath())
		return
	}
	Info("resuming after reboot: reporting job %d", state.JobID)
	uptime := "host rebooted and is back"
	if state.Note != "" {
		uptime += " (" + state.Note + ")"
	}
	if err := a.client.ReportStage(a.cfg.AgentSecret, state.JobID, "reboot", "done", uptime); err != nil {
		// Left in place deliberately: the next start tries again rather
		// than leaving the job stuck at 'reboot: running' forever.
		Error("could not report the resumed reboot for job %d: %v", state.JobID, err)
		return
	}
	os.Remove(StatePath())
}

func (a *Agent) stageHealthcheck() (string, string) {
	out, err := runScript("healthcheck.ps1", 5*time.Minute)
	if err != nil {
		return "failed", out
	}
	return "done", out
}
