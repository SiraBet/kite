// Package installer performs a kite agent installation.
//
// The same steps back the wizard and the silent flags, so an unattended
// install cannot drift from what the interactive one does -- there is
// one implementation and two front ends.
package installer

import (
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SiraBet/kite/agent-windows/internal/agent"
)

// The agent binary this installer deploys, written here by build.sh.
//
//go:embed payload
var payload embed.FS

const payloadPath = "payload/kite-agent.exe.gz"

// Options is everything an installation needs. Anything left empty that
// is genuinely required is reported before any change is made, rather
// than failing halfway through with files already on disk.
type Options struct {
	ProgramDir    string
	ControllerURL string
	Token         string
	Secret        string
	Hostname      string
	Team          string
	Role          string
	Insecure      bool
	CAFingerprint string
	PollInterval  int
}

// Progress reports a step as it starts. The wizard renders these; the
// silent path prints them, so an unattended install still leaves a
// trail that says how far it got.
type Progress func(string)

func (o Options) validate() error {
	if o.ControllerURL == "" {
		return fmt.Errorf("a controller URL is required")
	}
	if o.Token == "" && o.Secret == "" {
		return fmt.Errorf("either an enrollment token or the shared enrollment secret is required")
	}
	return nil
}

// HasPayload reports whether an agent binary was built into this
// installer. A setup binary without one cannot install anything, and
// saying so up front beats failing after the service is half-registered.
func HasPayload() bool {
	f, err := payload.Open(payloadPath)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// writeAgent expands the embedded agent into dir.
func writeAgent(dir string) (string, error) {
	compressed, err := payload.Open(payloadPath)
	if err != nil {
		return "", fmt.Errorf("this installer was built without an agent binary inside it " +
			"(build.sh did not write internal/installer/payload) -- it cannot install anything")
	}
	defer compressed.Close()

	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return "", fmt.Errorf("the embedded agent is not readable: %w", err)
	}
	defer reader.Close()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("could not create %s: %w", dir, err)
	}
	target := filepath.Join(dir, "kite-agent.exe")
	// Written to a temporary name and renamed, so a failure partway
	// through never leaves a truncated executable that the service
	// manager would happily try to start.
	tmp := target + ".new"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", fmt.Errorf("could not write into %s: %w", dir, err)
	}
	if _, err := io.Copy(file, reader); err != nil {
		file.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	// Windows refuses to replace a running executable, which is exactly
	// what an upgrade over a running service would hit.
	_ = os.Remove(target)
	if err := os.Rename(tmp, target); err != nil {
		return "", fmt.Errorf("could not replace %s (is the service still running?): %w", target, err)
	}
	return target, nil
}

// enroll exchanges the token or shared secret for this host's own
// credential and writes agent.conf.
func enroll(o Options) error {
	if o.CAFingerprint != "" {
		o.Insecure = false // a checked, pinned CA is what -insecure stood in for
	}
	return agent.Enroll(o.ControllerURL, o.Token, o.Secret, o.Hostname, o.Team, o.Role,
		o.Insecure, o.CAFingerprint, o.PollInterval)
}
