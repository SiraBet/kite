package agent

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// What the status window is allowed to see. Read-only on purpose: the
// window reports, it never drives. Runs are scheduled and gated on the
// controller, and a button here would let somebody who has never heard
// of a maintenance window start one.

// StatusSnapshot returns this process's own view. Only meaningful inside
// the process actually doing the polling -- the window is a different
// process and wants ReadPersistedStatus instead.
func StatusSnapshot() Status { return status.snapshot() }

// LoadStatusFromConfig fills in what can be known before any polling has
// happened. A host that is not enrolled is a normal state, not an error:
// the window says so and shows what fixes it.
func LoadStatusFromConfig() {
	cfg, err := LoadConfig()
	if err != nil {
		return
	}
	status.set(func(s *Status) {
		s.Enrolled, s.Controller, s.HostID = true, cfg.ControllerURL, cfg.HostID
		if name, err := os.Hostname(); err == nil {
			s.Hostname = name
		}
	})
}

// PollOnce runs a single poll/execute/report cycle. Used by the `once`
// command, which is the first thing to try when a host is not picking up
// work: it reports what happened to the console instead of the log.
func PollOnce(cfg *Config) error {
	a := NewAgent(cfg)
	a.ResumePendingReboot()
	instruction, _, err := a.client.PollNext(cfg.AgentSecret, cfg.PollInterval)
	if err != nil {
		return err
	}
	if instruction != nil {
		a.RunStage(instruction)
		return nil
	}
	Info("no pending job stage for this host")
	a.ReportInventory()
	return nil
}

// CheckController reports whether the controller answers, and says what
// went wrong when it does not. Used by the installer's "Test connection"
// button so a wrong URL or a blocked port is caught while somebody is
// still standing there to fix it, rather than becoming a host that
// silently never checks in.
//
// With a CA fingerprint, the controller's CA is fetched and checked
// first, and the connection checked against it -- as the agent will.
func CheckController(rawURL string, insecure bool, caFingerprint string) error {
	var caPEM []byte
	if caFingerprint != "" && !insecure {
		raw, err := FetchControllerCA(rawURL, caFingerprint)
		if err != nil {
			return err
		}
		caPEM = raw
	}
	client := newHTTPClient(insecure, caPEM)
	resp, err := client.Get(strings.TrimRight(rawURL, "/") + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the controller answered %s", resp.Status)
	}
	return nil
}
