package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	original := &Config{
		ControllerURL: "https://kite.lab", HostID: 12, AgentSecret: "abc123",
		PollInterval: 300, ErrorBackoff: 20, VerifyTLS: false,
	}
	if err := original.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if *loaded != *original {
		t.Errorf("loaded %+v, saved %+v", *loaded, *original)
	}

	// The file holds this host's credential to the controller.
	info, err := os.Stat(ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("agent.conf is readable beyond its owner: %v", mode)
	}
}

// verify_tls=false must survive a round trip as false. A missing key
// defaulting to true is right; a present false silently becoming true
// would turn an operator's explicit choice into the opposite one.
func TestConfigDefaultsOnlyFillMissingKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	raw := `{"controller_url":"https://kite.lab","host_id":3,"agent_secret":"s","verify_tls":false}`
	if err := os.WriteFile(filepath.Join(dir, "agent.conf"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyTLS {
		t.Error("an explicit verify_tls=false was overridden by the default")
	}
	if cfg.PollInterval != 900 || cfg.ErrorBackoff != 20 {
		t.Errorf("absent keys did not get their defaults: %+v", cfg)
	}
}

func TestLoadConfigSaysHowToFixNotEnrolled(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("loading a config that does not exist succeeded")
	}
	// Somebody reading this on a host needs the next step, not a bare
	// ENOENT: "not enrolled" is a normal state for a freshly copied exe.
	if !strings.Contains(err.Error(), "enroll") {
		t.Errorf("error does not say what to do: %v", err)
	}
}

func TestLoadConfigRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "agent.conf"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("a corrupt agent.conf loaded successfully")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestInstallDirHonoursOverride(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", "/somewhere/else")
	if InstallDir() != "/somewhere/else" {
		t.Errorf("InstallDir = %q", InstallDir())
	}
	for _, path := range []string{ConfigPath(), StatePath(), PublicDir()} {
		if filepath.Dir(path) != "/somewhere/else" {
			t.Errorf("%s is not under the install directory", path)
		}
	}
	if filepath.Dir(LogPath()) != filepath.Join("/somewhere/else", "status") {
		t.Errorf("log %s is not in the install directory's readable status folder", LogPath())
	}
}

func TestConfigSaveIsValidJSON(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	cfg := &Config{ControllerURL: "https://kite.lab", HostID: 1, AgentSecret: "s", PollInterval: 900}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	// Same shape as the Linux agent's agent.conf -- an operator
	// comparing two hosts should be reading the same keys.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"controller_url", "host_id", "agent_secret", "poll_interval", "verify_tls"} {
		if _, present := generic[key]; !present {
			t.Errorf("agent.conf is missing %q", key)
		}
	}
}

func TestNormalisePollInterval(t *testing.T) {
	cases := map[int]int{0: DefaultPollInterval, -5: DefaultPollInterval, 1: MinPollInterval,
		29: MinPollInterval, 30: 30, 900: 900}
	for given, want := range cases {
		if got := NormalisePollInterval(given); got != want {
			t.Errorf("NormalisePollInterval(%d) = %d, want %d", given, got, want)
		}
	}
}

// A config written by an installer that was never told an interval says
// zero. Sleeping zero seconds between polls makes the agent re-scan
// Windows Update without pause, so LoadConfig has to correct it.
func TestLoadConfigRejectsZeroPollInterval(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KITE_AGENT_DIR", dir)
	raw := `{"controller_url":"http://c:8000","host_id":2,"agent_secret":"s","poll_interval":0}`
	if err := os.WriteFile(filepath.Join(dir, "agent.conf"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval != DefaultPollInterval {
		t.Errorf("PollInterval = %d, want %d", cfg.PollInterval, DefaultPollInterval)
	}
}
