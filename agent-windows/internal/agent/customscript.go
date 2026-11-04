package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// A custom stage script gets the same ceiling as the Linux agent's
// (agent-linux/agent.py run_custom_script), so the two platforms fail the
// same way on a script that hangs.
const customScriptTimeout = time.Hour

// Stage output is reported to the controller and stored; the Linux agent
// keeps the last 4000 characters and so does this.
const customScriptOutputLimit = 4000

// runCustomScript executes a controller-supplied script instead of this
// stage's built-in handler.
//
// The contract matches the Linux agent exactly, because the same uploaded
// script should mean the same thing on both: exit 0 = done, any other exit
// code = failed, combined stdout+stderr is the stage output, and the run's
// data arrives through the environment rather than being templated into the
// script text — so one uploaded script keeps working as the exclude/pin list
// changes.
//
//	KITE_JOB_ID, KITE_HOSTNAME, KITE_STAGE
//	KITE_EXCLUDES  space-separated skip-mode package patterns
//	KITE_PINS      space-separated "pattern=version" for pin-mode
//	KITE_SEVERITY  the run's severity scope ('' / 'security' / a list)
func (a *Agent) runCustomScript(in *Instruction) (string, string) {
	// StageName is controller-supplied and is about to become a filename.
	// Anything that isn't a bare name could escape the script directory, so
	// reject it outright rather than writing wherever it points.
	stage := filepath.Base(in.StageName)
	if stage != in.StageName || stage == "" || stage == "." || stage == ".." ||
		strings.ContainsAny(in.StageName, `\/:`) {
		return "failed", fmt.Sprintf("refusing custom script: unsafe stage name %q", in.StageName)
	}

	dir := filepath.Join(InstallDir(), "stage_scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "failed", fmt.Sprintf("could not create %s: %v", dir, err)
	}
	path := filepath.Join(dir, stage+".ps1")
	if err := os.WriteFile(path, []byte(in.CustomScript), 0o600); err != nil {
		return "failed", fmt.Sprintf("could not write custom script: %v", err)
	}

	ctx, cancel := context.WithTimeout(runCtx, customScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, powershellExe(),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	cmd.Env = append(os.Environ(), customScriptEnv(in)...)

	cmd.WaitDelay = 15 * time.Second // see runScript: a leftover child must not hang the agent
	out, err := cmd.CombinedOutput()
	text := tailRunes(strings.TrimSpace(string(out)), customScriptOutputLimit)
	if note := stoppedNote(); note != "" {
		return "failed", fmt.Sprintf("custom script for %q %s", in.StageName, note)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "failed", fmt.Sprintf("custom script for %q timed out after %s", in.StageName, customScriptTimeout)
	}
	if err != nil {
		if text == "" {
			text = fmt.Sprintf("custom script for %q failed with no output: %v", in.StageName, err)
		}
		return "failed", text
	}
	return "done", text
}

// tailRunes keeps the last n characters, cutting on a rune boundary so a
// truncated line can't end in half a multi-byte character.
func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// customScriptEnv builds the KITE_* variables a stage script reads. Kept
// separate from the exec so it can be asserted without a PowerShell host.
func customScriptEnv(in *Instruction) []string {
	var skips, pins []string
	for _, rule := range in.Excludes {
		pattern, _ := rule["pkg_pattern"].(string)
		if pattern == "" {
			continue
		}
		if mode, _ := rule["mode"].(string); mode == "pin" {
			version, _ := rule["version"].(string)
			pins = append(pins, pattern+"="+version)
		} else {
			skips = append(skips, pattern)
		}
	}

	hostname := in.Hostname
	if hostname == "" {
		if name, err := os.Hostname(); err == nil {
			hostname = name
		}
	}

	return []string{
		fmt.Sprintf("KITE_JOB_ID=%d", in.JobID),
		"KITE_HOSTNAME=" + hostname,
		"KITE_STAGE=" + in.StageName,
		"KITE_EXCLUDES=" + strings.Join(skips, " "),
		"KITE_PINS=" + strings.Join(pins, " "),
		"KITE_SEVERITY=" + in.SeverityFilter,
	}
}
