package selfcfg

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The footer has two implementations: this package writes and reads it
// in Go, and the controller writes it in Python
// (controller/app/agent_package.py). A format with two implementations
// drifts unless something compares them, and the failure mode is silent
// -- an installer that looks fine and comes up unconfigured.
//
// Skipped when the controller source is not next to this checkout, so it
// never turns into a test that only passes on one machine.
func TestPythonWrittenFooterIsReadableByGo(t *testing.T) {
	module, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	controller := filepath.Join(module, "controller")
	if _, err := os.Stat(filepath.Join(controller, "app", "agent_package.py")); err != nil {
		t.Skip("controller source not present next to this checkout")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "setup.exe")
	dst := filepath.Join(dir, "setup-web01.exe")
	if err := os.WriteFile(src, []byte("MZ"+strings.Repeat("\x00", 2048)), 0o755); err != nil {
		t.Fatal(err)
	}

	script := `
import sys
sys.path.insert(0, sys.argv[1])
from app import agent_package
body = open(sys.argv[2], 'rb').read()
open(sys.argv[3], 'wb').write(agent_package.configure(body, {
    'controller_url': 'https://kite.lab',
    'token': 'tok-from-python',
    'hostname': 'WIN-FILE-01',
    'team': 'corporate',
    'insecure': True,
    'poll_interval': 300,
}))
`
	cmd := exec.Command("python3", "-c", script, controller, src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the controller's writer failed: %v\n%s", err, out)
	}

	got, ok := ReadFile(dst)
	if !ok {
		t.Fatal("Go could not read a footer written by the controller — the two implementations have drifted")
	}
	if got.ControllerURL != "https://kite.lab" {
		t.Errorf("controller_url = %q", got.ControllerURL)
	}
	if got.Token != "tok-from-python" {
		t.Errorf("token = %q", got.Token)
	}
	if got.Hostname != "WIN-FILE-01" || got.Team != "corporate" {
		t.Errorf("identity fields lost: %+v", *got)
	}
	// Types have to survive the crossing too, not just strings: a bool
	// or an int arriving as a string would fail at the far end.
	if !got.Insecure {
		t.Error("insecure did not survive as a bool")
	}
	if got.PollInterval != 300 {
		t.Errorf("poll_interval = %d, want 300", got.PollInterval)
	}
}
