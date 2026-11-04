package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// PollTimeout covers a normal round trip. The controller answers a poll
// immediately -- it never holds the connection open -- so this does not
// need to survive a long wait.
const PollTimeout = 15 * time.Second

// Client talks to the controller. The same endpoints the Linux agent
// uses, in the same order, so a misbehaving host is diagnosed the same
// way whichever OS it runs.
type Client struct {
	base   string
	hostID int
	http   *http.Client
}

func NewClient(cfg *Config) *Client {
	if !cfg.VerifyTLS {
		Warn("TLS certificate verification is DISABLED (verify_tls false in agent.conf). " +
			"Traffic to the controller has no protection against interception or tampering. " +
			"Re-enrol against a trusted certificate to fix this.")
	}
	var caPEM []byte
	if cfg.VerifyTLS && cfg.CACert != "" {
		raw, err := os.ReadFile(cfg.CACert)
		if err != nil {
			// Checked against nothing it could trust: every call fails,
			// which says so in the log rather than silently trusting more.
			Error("could not read the controller's CA %s: %v", cfg.CACert, err)
		}
		caPEM = raw
	}
	return &Client{
		base:   strings.TrimRight(cfg.ControllerURL, "/"),
		hostID: cfg.HostID,
		http:   newHTTPClient(!cfg.VerifyTLS, caPEM),
	}
}

// newHTTPClient builds the one HTTP client shape this agent uses, so the
// reachability check the installer runs and the polling the agent does
// cannot end up disagreeing about certificate verification. Set once on
// the client rather than per call, so every request it ever makes
// honours it -- not just the first.
func newHTTPClient(insecure bool, caPEM []byte) *http.Client {
	tlsCfg, err := tlsConfig(insecure, caPEM)
	if err != nil {
		Error("%v; nothing will be trusted for the controller", err)
		tlsCfg = &tls.Config{RootCAs: x509.NewCertPool()}
	}
	return &http.Client{Timeout: PollTimeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func (c *Client) url(path string) string {
	return fmt.Sprintf("%s/agent/%d%s", c.base, c.hostID, path)
}

func (c *Client) do(method, url string, body any, secret string) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, err
}

// Instruction is one stage the controller wants executed on this host.
type Instruction struct {
	JobID           int              `json:"job_id"`
	StageName       string           `json:"stage_name"`
	Excludes        []map[string]any `json:"excludes"`
	Hostname        string           `json:"hostname"`
	CustomScript    string           `json:"custom_script"`
	Containers      []map[string]any `json:"containers"`
	ContainerAction string           `json:"container_action"`
	SeverityFilter  string           `json:"severity_filter"`
}

// SelfUpdateHeader carries a target version on an otherwise-idle poll.
const SelfUpdateHeader = "X-Kite-Self-Update"

// PollNext asks for the next stage. The three return values separate "no
// work" from "the request itself failed" -- treating a network failure as
// "nothing to do" would leave a host silently idle while jobs pile up.
func (c *Client) PollNext(secret string, pollInterval int) (*Instruction, string, error) {
	url := fmt.Sprintf("%s?interval=%d&agent_version=%s", c.url("/jobs/next"), pollInterval, AgentVersion)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("poll returned %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	selfUpdate := resp.Header.Get(SelfUpdateHeader)

	// A poll with nothing to do returns a JSON null, not an object.
	if strings.TrimSpace(string(raw)) == "null" || len(raw) == 0 {
		return nil, selfUpdate, nil
	}
	instruction := &Instruction{}
	if err := json.Unmarshal(raw, instruction); err != nil {
		return nil, selfUpdate, fmt.Errorf("could not read the instruction: %w", err)
	}
	return instruction, selfUpdate, nil
}

func (c *Client) ReportStage(secret string, jobID int, stage, status, output string) error {
	// The controller stores stage output; a multi-megabyte transcript
	// helps nobody and would bloat every job listing that includes it.
	body := map[string]string{"status": status, "output": truncate(output, 8000)}
	url := fmt.Sprintf("%s/jobs/%d/stages/%s/report", c.url(""), jobID, stage)
	raw, code, err := c.do("POST", url, body, secret)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("report returned %d: %s", code, truncate(string(raw), 200))
	}
	return nil
}

// ReportInventory sends what this host is running. Best effort: a
// controller that rejects it must never stop the agent from patching.
// It returns whether the controller asked for the full software list
// again (its stored list isn't the one this agent's hash describes).
// hardwareID is read once per process: it doesn't change while it runs.
var hardwareID = func() func() string {
	var once sync.Once
	var id string
	return func() string { once.Do(func() { id = smbiosUUID() }); return id }
}()

func (c *Client) ReportInventory(secret string, updates []PendingUpdate, sources []SourceStatus, ok bool, assessErr string,
	network *Network, software *SoftwareReport) (bool, error) {
	// A nil slice marshals to JSON null, not []. That matters most when
	// the assessment failed and there is nothing to send -- which is
	// exactly the report carrying updates_ok=false, the signal saying
	// "this host's pending count is unknown, not zero".
	if updates == nil {
		updates = []PendingUpdate{}
	}
	if sources == nil {
		sources = []SourceStatus{}
	}
	body := map[string]any{
		"runtime":        "",
		"containers":     []any{},
		"updates":        updates,
		"update_sources": sources,
		// Kept for the host-level "is this patched" flags and for a
		// controller too old to read update_sources: both carry the OS
		// source's result.
		"updates_ok":    ok,
		"updates_error": assessErr,
		// Recorded by the controller for a host with none on record yet.
		"smbios_uuid": hardwareID(),
	}
	// Omitted rather than sent empty when not collected: the controller
	// reads a missing "network" as "this agent doesn't report it".
	if network != nil {
		body["network"] = network
	}
	if software != nil {
		body["software"] = software
	}
	raw, code, err := c.do("POST", c.url("/inventory"), body, secret)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("inventory returned %d", code)
	}
	var reply struct {
		SoftwareResend bool `json:"software_resend"`
	}
	_ = json.Unmarshal(raw, &reply)
	return reply.SoftwareResend, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
