package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Log writes the agent's operational log.
//
// The status window reads this file rather than any in-process buffer:
// it runs as a separate process from the service, so there is no shared
// memory to read, and the file is the only thing both can see.
type Log struct {
	mu      sync.Mutex
	file    *os.File
	written int64 // since the file was opened or last checked
}

const maxLogBytes = 5 << 20

var logger = &Log{}

// OpenLog starts writing to PublicDir()/agent.log. A log that cannot be
// opened is not fatal: an agent that refuses to run because it cannot
// write a log is worse than one that runs and says so on stderr.
func OpenLog() {
	if err := os.MkdirAll(PublicDir(), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %v\n", PublicDir(), err)
		return
	}
	moveOldLog()
	f, err := os.OpenFile(LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %v\n", LogPath(), err)
		return
	}
	logger.mu.Lock()
	logger.file = f
	logger.mu.Unlock()
	logger.rotateIfLarge()
}

// rotateIfLarge keeps one previous log alongside the current one. A patch
// agent writing command output can produce a lot on a bad day, and an
// unbounded log on a system drive is its own outage.
func (l *Log) rotateIfLarge() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rotateLocked()
}

// rotateLocked: with l.mu held. Called at start and every megabyte
// written, so a long-running agent's log stays bounded too.
func (l *Log) rotateLocked() {
	l.written = 0
	info, err := os.Stat(LogPath())
	if err != nil || info.Size() < maxLogBytes {
		return
	}
	if l.file != nil {
		l.file.Close()
	}
	_ = os.Remove(LogPath() + ".1")
	_ = os.Rename(LogPath(), LogPath()+".1")
	l.file, _ = os.OpenFile(LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
}

func (l *Log) write(level, format string, args ...any) {
	line := fmt.Sprintf("%s %-5s %s\n",
		time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		n, _ := l.file.WriteString(line)
		if l.written += int64(n); l.written >= 1<<20 {
			l.rotateLocked()
		}
	}
	fmt.Print(line)
}

// moveOldLog brings a log kept directly in InstallDir, where the window
// can't read it, into PublicDir, once.
func moveOldLog() {
	old := filepath.Join(InstallDir(), "agent.log")
	if _, err := os.Stat(LogPath()); err == nil {
		return
	}
	if _, err := os.Stat(old); err == nil {
		_ = os.Rename(old, LogPath())
		_ = os.Rename(old+".1", LogPath()+".1")
		_ = os.Remove(filepath.Join(InstallDir(), "status.json"))
	}
}

func Info(format string, args ...any)  { logger.write("INFO", format, args...) }
func Warn(format string, args ...any)  { logger.write("WARN", format, args...) }
func Error(format string, args ...any) { logger.write("ERROR", format, args...) }
