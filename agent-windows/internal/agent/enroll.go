package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type enrollResponse struct {
	HostID      int    `json:"host_id"`
	AgentSecret string `json:"agent_secret"`
	Detail      string `json:"detail"`
}

// Enroll exchanges a one-time token, or the shared secret, for this
// host's own long-lived credential. The response is shown once and
// written to agent.conf; nothing else ever sees it.
//
// With caFingerprint, the controller's root CA is downloaded and checked
// against it first, and every call from then on -- this one included --
// is checked against that root alone.
func Enroll(controller, token, secret, hostname, team, role string, insecure bool, caFingerprint string, pollInterval int) error {
	controller = strings.TrimRight(controller, "/")
	pollInterval = NormalisePollInterval(pollInterval)
	if hostname == "" {
		name, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("could not determine this host's name: %w", err)
		}
		hostname = name
	}
	if insecure && caFingerprint != "" {
		return fmt.Errorf("-insecure turns off the certificate check -ca-fingerprint sets up; use one or the other")
	}
	var caPEM []byte
	if caFingerprint != "" {
		raw, err := FetchControllerCA(controller, caFingerprint)
		if err != nil {
			return err
		}
		caPEM = raw
	}
	if insecure {
		fmt.Fprintln(os.Stderr,
			"WARNING: TLS certificate verification is DISABLED (-insecure). The long-lived agent\n"+
				"credential this is about to receive, and every command the agent later runs as SYSTEM,\n"+
				"will cross the network with no protection against interception or tampering. Use this\n"+
				"only on a trusted network, and drop it once the controller has a certificate this host\n"+
				"trusts.")
	}

	body := map[string]any{
		"os_version":            osVersion(),
		"smbios_uuid":           smbiosUUID(),
		"os_family":             "windows",
		"poll_interval_seconds": pollInterval,
	}
	var endpoint string
	switch {
	case token != "":
		endpoint, body["token"] = controller+"/agent/enroll", token
	case secret != "":
		endpoint = controller + "/agent/self-enroll"
		body["secret"], body["hostname"], body["team"], body["role"] = secret, hostname, team, role
	default:
		return fmt.Errorf("need either -token or -secret")
	}

	tlsCfg, err := tlsConfig(insecure, caPEM)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	raw, _ := json.Marshal(body)
	resp, err := postWithRetry(client, endpoint, raw, enrollAttempts, enrollRetryWait)
	if err != nil {
		return fmt.Errorf("could not reach %s (tried %d times): %w", endpoint, enrollAttempts, err)
	}
	defer resp.Body.Close()

	var parsed enrollResponse
	decoded := json.NewDecoder(resp.Body).Decode(&parsed)
	if resp.StatusCode != http.StatusOK {
		if parsed.Detail != "" {
			return fmt.Errorf("enrollment refused (%d): %s", resp.StatusCode, parsed.Detail)
		}
		return fmt.Errorf("enrollment refused (%d)", resp.StatusCode)
	}
	if decoded != nil || parsed.AgentSecret == "" {
		return fmt.Errorf("the controller's reply did not contain a credential")
	}

	cfg := &Config{
		ControllerURL: controller, HostID: parsed.HostID, AgentSecret: parsed.AgentSecret,
		PollInterval: pollInterval, ErrorBackoff: 20, VerifyTLS: !insecure,
	}
	if caPEM != nil {
		if err := saveCA(caPEM); err != nil {
			return fmt.Errorf("enrolled as host %d, but could not save the controller's CA: %w", parsed.HostID, err)
		}
		cfg.CACert = CAPath()
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("enrolled as host %d, but could not write %s: %w", parsed.HostID, ConfigPath(), err)
	}
	fmt.Printf("Enrolled as host_id=%d (%s). Config written to %s\n", parsed.HostID, hostname, ConfigPath())
	fmt.Printf("Next: kite-agent install    (registers and starts the service)\n")
	return nil
}

// A network hiccup between the host and the controller (a firewall
// state table, a link coming up) shouldn't fail an install that would
// work a few seconds later. Only connection failures are retried: an
// answer from the controller, even a refusal, is final.
var (
	enrollAttempts  = 3
	enrollRetryWait = 5 * time.Second
)

func postWithRetry(client *http.Client, endpoint string, raw []byte, attempts int, wait time.Duration) (*http.Response, error) {
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			fmt.Printf("Couldn't reach the controller (%v); retrying in %s...\n", err, wait)
			time.Sleep(wait)
		}
		var resp *http.Response
		resp, err = client.Post(endpoint, "application/json", strings.NewReader(string(raw)))
		if err == nil {
			return resp, nil
		}
	}
	return nil, err
}

// smbiosUUID is this machine's hardware id, or "" when Windows won't say
// (or says nothing useful: all zeros or all Fs on some hardware).
func smbiosUUID() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	out, err := runScript("smbios.ps1", 60*time.Second)
	uuid := strings.ToLower(strings.TrimSpace(out))
	if err != nil || len(uuid) != 36 || strings.Trim(uuid, "0-") == "" || strings.Trim(uuid, "f-") == "" {
		return ""
	}
	return uuid
}

// osVersion is shown on the Fleet page. Best effort: a host that cannot
// describe itself still enrols.
func osVersion() string {
	if runtime.GOOS != "windows" {
		return runtime.GOOS
	}
	out, err := runScript("osversion.ps1", 60*time.Second)
	if err != nil || out == "" {
		return "Windows"
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}
