package agent

import "testing"

// The status window and the `status` command read status.json; they must
// never write it. Before this was enforced, opening the window overwrote
// the service's live status -- last poll, pending count and all -- with a
// bare config-only snapshot, then read that clobbered file back.
func TestStatusPublishingIsOptIn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	restore := publishStatus.Load()
	defer publishStatus.Store(restore)

	// A reader process: publishing off. A set must not touch the file.
	publishStatus.Store(false)
	status.set(func(s *Status) { s.PendingCount = 7 })
	if _, ok := ReadPersistedStatus(); ok {
		t.Fatal("status.json was written while publishing was disabled")
	}

	// A poller enables publishing (NewAgent does this); now it persists.
	EnableStatusPublishing()
	status.set(func(s *Status) { s.PendingCount = 7 })
	got, ok := ReadPersistedStatus()
	if !ok || got.PendingCount != 7 {
		t.Fatalf("expected published PendingCount 7, got ok=%v count=%d", ok, got.PendingCount)
	}
}

func TestNewAgentEnablesPublishing(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	restore := publishStatus.Load()
	defer publishStatus.Store(restore)
	publishStatus.Store(false)

	NewAgent(&Config{ControllerURL: "http://c:8000", HostID: 2})
	if !publishStatus.Load() {
		t.Fatal("NewAgent did not enable status publishing")
	}
	if _, ok := ReadPersistedStatus(); !ok {
		t.Fatal("NewAgent did not publish an initial status")
	}
}
