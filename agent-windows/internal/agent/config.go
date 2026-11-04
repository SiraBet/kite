package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Config is the agent's identity and where to reach the controller. It is
// written once by `enroll` and read by every later invocation.
//
// Same shape as the Linux agent's agent.conf, deliberately: one contract
// means one thing to reason about when a host misbehaves, whichever OS it
// runs.
type Config struct {
	ControllerURL string `json:"controller_url"`
	HostID        int    `json:"host_id"`
	AgentSecret   string `json:"agent_secret"`
	PollInterval  int    `json:"poll_interval"`
	ErrorBackoff  int    `json:"error_backoff"`
	VerifyTLS     bool   `json:"verify_tls"`
	// The controller's root CA, once pinned (see controllerca.go): with
	// it, every call is checked against that root alone.
	CACert string `json:"ca_cert,omitempty"`
}

// DefaultPollInterval is how often the agent asks the controller for work
// when the config does not say. MinPollInterval is the floor: every poll
// that finds nothing to do still runs a full Windows Update assessment,
// which takes seconds and costs real disk and CPU on the host, so a very
// short interval leaves the machine scanning itself continuously.
const (
	DefaultPollInterval = 900
	MinPollInterval     = 30
)

// NormalisePollInterval turns an unset or too-eager interval into one the
// agent can sleep on. Zero arrives from an install that was never given a
// value; sleeping zero seconds makes Run spin instead of poll.
func NormalisePollInterval(seconds int) int {
	if seconds <= 0 {
		return DefaultPollInterval
	}
	if seconds < MinPollInterval {
		return MinPollInterval
	}
	return seconds
}

// InstallDir is where the binary, config and log live. Under ProgramData
// rather than Program Files: the service writes its log and state here,
// and Program Files is read-only to everything but installers by design.
func InstallDir() string {
	if dir := os.Getenv("KITE_AGENT_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "kite")
	}
	return "/etc/kite"
}

// ProgramDir is where the executable lives. Separate from InstallDir on
// purpose: Program Files is the conventional home for a service binary
// and is administrator-writable only, while state that the service
// writes constantly belongs under ProgramData. Keeping a running
// service's executable in the same directory it writes logs into works,
// but it puts the binary in a directory that exists to be written to.
func ProgramDir() string {
	if dir := os.Getenv("KITE_PROGRAM_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "kite")
	}
	return "/opt/kite-agent"
}

// AgentExePath is the installed binary the service is registered against.
func AgentExePath() string { return filepath.Join(ProgramDir(), "kite-agent.exe") }

func ConfigPath() string { return filepath.Join(InstallDir(), "agent.conf") }
func StatePath() string  { return filepath.Join(InstallDir(), "pending_reboot.json") }

// PublicDir holds what the status window shows -- status.json and the
// log -- readable by the host's users. InstallDir itself is locked to
// SYSTEM and Administrators because agent.conf holds this host's
// credential, and the window runs as the signed-in user without
// elevation, so it couldn't read anything there (see OpenUpPublicDir).
func PublicDir() string { return filepath.Join(InstallDir(), "status") }
func LogPath() string   { return filepath.Join(PublicDir(), "agent.log") }

// StateUnreadable reports that the agent's files exist but this process
// isn't allowed to read them -- so the window can say that, rather than
// "not enrolled".
func StateUnreadable() bool {
	for _, p := range []string{StatusPath(), ConfigPath()} {
		if _, err := os.Open(p); err != nil && errors.Is(err, fs.ErrPermission) {
			return true
		}
	}
	return false
}

func LoadConfig() (*Config, error) {
	raw, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not enrolled yet: %s does not exist. Run `kite-agent enroll` first", ConfigPath())
		}
		return nil, err
	}
	cfg := &Config{PollInterval: DefaultPollInterval, ErrorBackoff: 20, VerifyTLS: true}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", ConfigPath(), err)
	}
	if normalised := NormalisePollInterval(cfg.PollInterval); normalised != cfg.PollInterval {
		Warn("poll_interval in %s is %ds; using %ds instead", ConfigPath(), cfg.PollInterval, normalised)
		cfg.PollInterval = normalised
	}
	return cfg, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// 0600: this file holds a credential that is this host's identity to
	// the controller. On Windows the directory ACL set by `install` is
	// what actually restricts it; the mode still matters when the agent
	// is run from a non-Windows host during development.
	return os.WriteFile(ConfigPath(), raw, 0o600)
}
