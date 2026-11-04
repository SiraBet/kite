package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// The service and the status window are different processes -- and on
// Windows a service runs in session 0, where it cannot show a window at
// all. So the two cannot share memory, and the running agent publishes
// what it knows to a file the window reads.
//
// A file rather than a socket or a named pipe: nothing listens, there
// are no pipe ACLs to get wrong, and it still answers when the service
// is stopped. That last case matters most -- somebody opening this
// window is usually asking why the agent is not working, and "the
// service is not running, here is the last thing it did" is the answer
// an IPC channel could not have given them.

func StatusPath() string { return filepath.Join(PublicDir(), "status.json") }

// persistStatus writes via a temporary file and a rename, so a reader
// never catches a half-written file. Failures are ignored on purpose:
// not being able to publish status must never stop a host from being
// patched.
func persistStatus(s Status) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(PublicDir(), 0o755)
	tmp := StatusPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, StatusPath())
}

// ReadPersistedStatus returns what the running agent last published.
// A zero Status with ok=false means nothing has ever been written --
// which is what a host that has never run the service looks like, and
// is different from a host whose agent is failing.
func ReadPersistedStatus() (Status, bool) {
	raw, err := os.ReadFile(StatusPath())
	if err != nil {
		return Status{Version: AgentVersion}, false
	}
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		return Status{Version: AgentVersion}, false
	}
	return s, true
}

// TailLogLines returns the last `max` lines of the agent log, oldest
// first. Read from the file rather than an in-process buffer because the
// window is a different process than the one doing the logging.
func TailLogLines(max int) []string {
	file, err := os.Open(LogPath())
	if err != nil {
		return nil
	}
	defer file.Close()

	// A ring over the whole file: the log is capped at 5MB by rotation,
	// so scanning it costs little and this avoids seeking to a byte
	// offset that could land mid-line.
	ring := make([]string, 0, max)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if len(ring) == max {
			ring = ring[1:]
		}
		ring = append(ring, scanner.Text())
	}
	return ring
}
