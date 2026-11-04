package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeExit int

func (f fakeExit) Error() string { return fmt.Sprintf("exit status %d", int(f)) }
func (f fakeExit) ExitCode() int { return int(f) }

func withShutdown(t *testing.T, results ...error) *[][]string {
	t.Helper()
	calls := &[][]string{}
	old := runShutdown
	runShutdown = func(args ...string) error {
		*calls = append(*calls, args)
		if len(results) == 0 {
			return nil
		}
		r := results[0]
		results = results[1:]
		return r
	}
	t.Cleanup(func() { runShutdown = old })
	return calls
}

func TestRestartIsIssuedNormally(t *testing.T) {
	calls := withShutdown(t, nil)
	note, err := restartNow("c")
	if err != nil || note != "" || len(*calls) != 1 || (*calls)[0][0] != "/r" {
		t.Fatalf("note=%q err=%v calls=%v", note, err, *calls)
	}
}

// Windows Update had already scheduled its own restart: cancel it and
// restart now, rather than failing the run.
func TestAnAlreadyScheduledRestartIsReplacedWithAnImmediateOne(t *testing.T) {
	calls := withShutdown(t, fakeExit(1190), nil, nil)
	note, err := restartNow("c")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(*calls); got != "[[/r /t 5 /c c] [/a] [/r /t 5 /c c]]" {
		t.Errorf("calls = %s", got)
	}
	if !strings.Contains(note, "already scheduled") {
		t.Errorf("note = %q", note)
	}
}

func TestFailuresAreDescribedInWords(t *testing.T) {
	withShutdown(t, fakeExit(5))
	if _, err := restartNow("c"); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("err = %v", err)
	}
	withShutdown(t, fakeExit(1190), nil, fakeExit(1190))
	if _, err := restartNow("c"); err == nil || !strings.Contains(err.Error(), "replacing it with an immediate one failed") {
		t.Errorf("err = %v", err)
	}
}

// Error 1115: the machine is already going down, which is the restart
// the run waits for -- not a reason to fail the stage.
func TestAMachineAlreadyShuttingDownCountsAsRestarting(t *testing.T) {
	withShutdown(t, fakeExit(1115))
	if note, err := restartNow("c"); err != nil || !strings.Contains(note, "already shutting down") {
		t.Errorf("note=%q err=%v", note, err)
	}
	withShutdown(t, fakeExit(1190), nil, fakeExit(1115))
	if note, err := restartNow("c"); err != nil || !strings.Contains(note, "already shutting down") {
		t.Errorf("after replacing a scheduled restart: note=%q err=%v", note, err)
	}
}

// The controller keeps handing out the reboot stage until it's reported.
// Once the agent has asked for the restart it must not poll again and
// run the stage a second time: that cancelled its own countdown and
// started a new one, every few seconds, until shutdown failed it.
func TestRestartIsAskedForOnceThenTheAgentWaits(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	calls := withShutdown(t)
	oldCheck, oldWait := rebootCheck, restartWait
	rebootCheck = func() (string, error) { return "yes", nil }
	restartWait = time.Hour
	t.Cleanup(func() { rebootCheck, restartWait = oldCheck, oldWait })

	var polls atomic.Int32
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) > 1 {
			close(stop) // a second poll is the bug; end the run so the test fails rather than hangs
		}
		fmt.Fprint(w, `{"job_id": 3, "stage_name": "reboot"}`)
	}))
	defer srv.Close()
	cfg := &Config{ControllerURL: srv.URL, HostID: 7, VerifyTLS: true, PollInterval: 60, ErrorBackoff: 1}
	a := &Agent{cfg: cfg, client: NewClient(cfg)}

	done := make(chan struct{})
	go func() { a.Run(stop); close(done) }()
	time.Sleep(300 * time.Millisecond)
	if polls.Load() == 1 {
		close(stop)
	}
	<-done
	if n := polls.Load(); n != 1 {
		t.Errorf("polled %d times after asking for the restart, want 1", n)
	}
	if len(*calls) != 1 {
		t.Errorf("shutdown calls = %v, want one restart", *calls)
	}
}
