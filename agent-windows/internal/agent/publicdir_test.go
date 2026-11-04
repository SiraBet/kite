package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The status window runs unelevated; InstallDir is locked to SYSTEM and
// Administrators because agent.conf holds the host's credential. So what
// the window reads lives in PublicDir, and the credential never does.
func TestWhatTheWindowReadsIsInThePublicDirAndTheSecretIsNot(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	for _, p := range []string{LogPath(), StatusPath()} {
		if filepath.Dir(p) != PublicDir() {
			t.Errorf("%s is not in %s", p, PublicDir())
		}
	}
	if strings.HasPrefix(ConfigPath(), PublicDir()) {
		t.Errorf("agent.conf (%s) must stay out of the readable folder", ConfigPath())
	}
}

func TestStatusIsPublishedIntoThePublicDir(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	persistStatus(Status{Enrolled: true, HostID: 4, Version: AgentVersion})
	s, ok := ReadPersistedStatus()
	if !ok || !s.Enrolled || s.HostID != 4 {
		t.Fatalf("status = %+v ok=%v", s, ok)
	}
}

func TestAnOlderAgentsLogMovesIntoThePublicDirOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	os.WriteFile(filepath.Join(dir, "agent.log"), []byte("old line\n"), 0o640)
	os.WriteFile(filepath.Join(dir, "status.json"), []byte("{}"), 0o644)
	os.MkdirAll(PublicDir(), 0o755)
	moveOldLog()
	if got, _ := os.ReadFile(LogPath()); string(got) != "old line\n" {
		t.Errorf("log = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "status.json")); !os.IsNotExist(err) {
		t.Error("the old, unreadable status.json was left behind")
	}
	os.WriteFile(filepath.Join(dir, "agent.log"), []byte("another\n"), 0o640)
	moveOldLog() // a log already in place is never overwritten
	if got, _ := os.ReadFile(LogPath()); string(got) != "old line\n" {
		t.Errorf("log overwritten: %q", got)
	}
}

func TestUnreadableStateIsToldApartFromNotEnrolled(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	if StateUnreadable() {
		t.Fatal("nothing there yet is not 'unreadable'")
	}
	os.WriteFile(ConfigPath(), []byte("{}"), 0o000)
	if !StateUnreadable() {
		t.Error("a config this account can't open should read as unreadable")
	}
}
