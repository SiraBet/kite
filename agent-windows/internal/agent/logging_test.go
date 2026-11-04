package agent

import (
	"os"
	"strings"
	"testing"
)

// The log is rotated as it grows, not only when the agent starts.
func TestTheLogIsRotatedWhileRunning(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	old := logger
	logger = &Log{}
	t.Cleanup(func() { logger.file.Close(); logger = old })
	OpenLog()
	big := strings.Repeat("x", 1000)
	for i := 0; i < 6*1100; i++ { // a little over 6 MB
		Info("%s", big)
	}
	info, err := os.Stat(LogPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maxLogBytes+(1<<20)+2000 {
		t.Errorf("log is %d bytes; it wasn't rotated", info.Size())
	}
	if _, err := os.Stat(LogPath() + ".1"); err != nil {
		t.Error("no rotated log")
	}
}
