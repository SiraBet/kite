package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Self-update: the controller says which version this agent should run
// (a response header on an idle poll); the agent fetches that build of
// kite-agent.exe from the controller, checks it is intact and really
// that version, swaps it in beside the running one and restarts the
// service. Only ever upward, and a failed attempt waits an hour before
// the next, so a broken download can't turn every poll into a 10 MB fetch.

const selfUpdateRetry = time.Hour

var lastUpdateFailure = map[string]time.Time{}

// versionNewer reports whether want is a higher dotted version than have.
// Anything that isn't plain numbers is never newer: a malformed target
// must not trigger a download.
func versionNewer(want, have string) bool {
	w, okW := versionParts(want)
	h, okH := versionParts(have)
	if !okW || !okH {
		return false
	}
	for i := 0; i < len(w) || i < len(h); i++ {
		var a, b int
		if i < len(w) {
			a = w[i]
		}
		if i < len(h) {
			b = h[i]
		}
		if a != b {
			return a > b
		}
	}
	return false
}

func versionParts(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// downloadedAgent is a fetched build, checked against what the controller
// said it is.
type downloadedAgent struct {
	data    []byte
	version string
}

// fetchAgentBuild downloads the controller's Windows agent and checks the
// X-Kite-Sha256 and X-Kite-Agent-Version it was served with.
func (c *Client) fetchAgentBuild(want string) (*downloadedAgent, error) {
	httpClient := *c.http
	httpClient.Timeout = 5 * time.Minute // ~10 MB, over whatever link this host has
	resp, err := httpClient.Get(c.base + "/download/agent/windows")
	if err != nil {
		return nil, fmt.Errorf("could not download the agent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the controller answered %d for the agent download", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return nil, fmt.Errorf("the download was cut short: %w", err)
	}
	return checkAgentBuild(data, resp.Header.Get("X-Kite-Sha256"), resp.Header.Get("X-Kite-Agent-Version"), want)
}

// checkAgentBuild is the trust decision, separate so it can be tested.
// Both headers are required: without them there is nothing to check the
// download against, and swapping in an unchecked binary isn't worth it.
func checkAgentBuild(data []byte, sum, version, want string) (*downloadedAgent, error) {
	if sum == "" || version == "" {
		return nil, fmt.Errorf("the controller didn't say which version and checksum it served (controller too old?)")
	}
	got := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(got[:]), sum) {
		return nil, fmt.Errorf("the downloaded agent doesn't match its checksum")
	}
	if version != want {
		return nil, fmt.Errorf("the controller serves agent %s, not the %s it asked for", version, want)
	}
	return &downloadedAgent{data: data, version: version}, nil
}

// swapBinary puts staged in place of current. Windows won't overwrite a
// running .exe but will rename one, so the running binary moves aside to
// .old first; if the second rename fails it moves back. The .old copy is
// removed once the new agent has reached the controller (see checkNewBinary).
func swapBinary(current, staged string) error {
	old := current + ".old"
	_ = os.Remove(old)
	if err := os.Rename(current, old); err != nil {
		return fmt.Errorf("could not move the running agent aside: %w", err)
	}
	if err := os.Rename(staged, current); err != nil {
		_ = os.Rename(old, current)
		return fmt.Errorf("could not put the new agent in place: %w", err)
	}
	return nil
}

// After a self-update the previous binary is kept as .old until the new
// one has reached the controller once. checkNewBinary runs at every start
// while it's kept, and counts: a new binary that has started
// maxUntriedStarts times without reaching the controller (it crashes,
// say) is replaced by the previous one again.
const maxUntriedStarts = 3

func updateTriesPath() string { return AgentExePath() + ".tries" }

// checkNewBinary returns true when it has put the previous binary back
// and asked for a restart onto it: the caller stops.
func checkNewBinary() bool {
	_ = os.Remove(AgentExePath() + ".new") // a staged download that never got swapped in
	old := AgentExePath() + ".old"
	if _, err := os.Stat(old); err != nil {
		return false
	}
	tries := 0
	if raw, err := os.ReadFile(updateTriesPath()); err == nil {
		tries, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
	}
	tries++
	if tries <= maxUntriedStarts {
		_ = os.WriteFile(updateTriesPath(), []byte(strconv.Itoa(tries)), 0o644)
		return false
	}
	Error("self-update: agent %s started %d times without reaching the controller; going back to the previous agent",
		AgentVersion, maxUntriedStarts)
	_ = os.Remove(AgentExePath() + ".bad")
	if err := os.Rename(AgentExePath(), AgentExePath()+".bad"); err != nil {
		Error("could not move this agent aside: %v", err)
		return false
	}
	if err := os.Rename(old, AgentExePath()); err != nil {
		_ = os.Rename(AgentExePath()+".bad", AgentExePath())
		Error("could not put the previous agent back: %v", err)
		return false
	}
	_ = os.Remove(updateTriesPath())
	if err := restartServiceDetached(); err != nil {
		Error("previous agent put back; it runs from the next service start (%v)", err)
	}
	return true
}

// newBinaryHealthy: this binary has reached the controller, so the
// previous one isn't needed as a way back any more.
func newBinaryHealthy() {
	_ = os.Remove(AgentExePath() + ".old")
	_ = os.Remove(updateTriesPath())
}

// maybeSelfUpdate acts on the controller's target version. Returns true
// when a new binary is in place and the service restart has been asked
// for, so the caller can stop polling and let the restart happen.
func (a *Agent) maybeSelfUpdate(target string) bool {
	if !versionNewer(target, AgentVersion) {
		return false
	}
	if at, ok := lastUpdateFailure[target]; ok && time.Since(at) < selfUpdateRetry {
		return false
	}
	if !RunningAsService() {
		Info("controller wants agent %s (this is %s); running outside the service, so not updating in place", target, AgentVersion)
		return false
	}
	fail := func(err error) bool {
		lastUpdateFailure[target] = time.Now()
		Warn("self-update to %s failed: %v", target, err)
		return false
	}
	Info("self-update: %s -> %s", AgentVersion, target)
	build, err := a.client.fetchAgentBuild(target)
	if err != nil {
		return fail(err)
	}
	staged := AgentExePath() + ".new"
	if err := os.WriteFile(staged, build.data, 0o755); err != nil {
		return fail(fmt.Errorf("could not write %s: %w", staged, err))
	}
	if err := swapBinary(AgentExePath(), staged); err != nil {
		_ = os.Remove(staged)
		return fail(err)
	}
	if err := restartServiceDetached(); err != nil {
		// The new binary is in place; it runs from the next service start.
		return fail(fmt.Errorf("agent %s installed, but the service restart failed (it takes effect on the next start): %w", target, err))
	}
	Info("self-update: agent %s installed; restarting the service", target)
	return true
}
