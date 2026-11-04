package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The controller's root CA. With its default self-signed setup the
// controller publishes the root its certificates come from
// (/download/ca.crt) and the console shows the root's SHA-256
// fingerprint; once a host has checked that fingerprint, every call to
// the controller is checked against that root alone.

// CAPath is where the pinned root is kept.
func CAPath() string { return filepath.Join(InstallDir(), "controller-ca.crt") }

// parseCA returns the one certificate in a PEM block, or an error.
func parseCA(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || strings.Contains(string(rest), "BEGIN") {
		return nil, fmt.Errorf("not a single PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// CAFingerprint is SHA-256 of the certificate (DER), lowercase hex: what
// the console and a browser show for it.
func CAFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func normaliseFingerprint(fp string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(fp) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// tlsConfig is how every client in this agent checks the controller:
// not at all (insecure), against the pinned root alone (caPEM), or
// against the system's CAs (neither).
func tlsConfig(insecure bool, caPEM []byte) (*tls.Config, error) {
	if insecure {
		return &tls.Config{InsecureSkipVerify: true}, nil // #nosec G402 -- opt-in, see enroll -insecure
	}
	if len(caPEM) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the controller's CA isn't a usable certificate")
	}
	return &tls.Config{RootCAs: pool}, nil
}

// downloadCA fetches /download/ca.crt without checking the connection:
// nothing is trusted until the content is checked. Returns nil, nil when
// the controller publishes none (a public certificate).
func downloadCA(client *http.Client, controller string) ([]byte, error) {
	resp, err := client.Get(strings.TrimRight(controller, "/") + "/download/ca.crt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading the controller's CA: %s", resp.Status)
	}
	return raw, nil
}

// FetchControllerCA downloads the controller's root and checks it against
// the fingerprint the console showed.
func FetchControllerCA(controller, fingerprint string) ([]byte, error) {
	insecure, _ := tlsConfig(true, nil)
	raw, err := downloadCA(&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: insecure}}, controller)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("the controller publishes no CA of its own (it has a public certificate): enrol without a fingerprint")
	}
	cert, err := parseCA(raw)
	if err != nil {
		return nil, fmt.Errorf("the controller's CA download: %w", err)
	}
	if got, want := CAFingerprint(cert), normaliseFingerprint(fingerprint); got != want {
		return nil, fmt.Errorf("the controller's CA has fingerprint %s, not the %s you were given: "+
			"not enrolling, something may be impersonating the controller", got, want)
	}
	return raw, nil
}

func saveCA(raw []byte) error {
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return err
	}
	tmp := CAPath() + ".new"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, CAPath())
}

// PinControllerCA moves an agent enrolled with -insecure to checking the
// controller's certificate: against the controller's own root when it
// publishes one (taken once, over the connection this agent already
// trusts), else against the system's CAs. Only after a request checked
// that way succeeds: a switch that locked the agent out of its
// controller would be worse than none. Returns a note for the log, or
// "" when there was nothing to do.
func (a *Agent) PinControllerCA() string {
	if a.cfg.VerifyTLS {
		return ""
	}
	insecure, _ := tlsConfig(true, nil)
	raw, err := downloadCA(&http.Client{Timeout: PollTimeout, Transport: &http.Transport{TLSClientConfig: insecure}},
		a.cfg.ControllerURL)
	if err != nil {
		return fmt.Sprintf("controller certificate: controller not reachable (%v)", err)
	}
	if raw != nil {
		if _, err := parseCA(raw); err != nil {
			return "controller certificate: the controller's CA download isn't a certificate; checks stay off"
		}
	}
	tlsCfg, err := tlsConfig(false, raw)
	if err != nil {
		return "controller certificate: " + err.Error()
	}
	check := &http.Client{Timeout: PollTimeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := check.Get(strings.TrimRight(a.cfg.ControllerURL, "/") + "/health")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("the controller answered %s", resp.Status)
		}
	}
	if err != nil {
		return fmt.Sprintf("controller certificate: still not checked: a checked request failed (%v)", err)
	}
	against := "the system CAs"
	cfg := *a.cfg
	cfg.VerifyTLS = true
	if raw != nil {
		if err := saveCA(raw); err != nil {
			return fmt.Sprintf("controller certificate: couldn't save its CA (%v); checks stay off", err)
		}
		cfg.CACert, against = CAPath(), "its CA at "+CAPath()
	}
	if err := cfg.Save(); err != nil {
		return fmt.Sprintf("controller certificate: couldn't save the config (%v); checks stay off", err)
	}
	a.cfg = &cfg
	a.client = NewClient(a.cfg)
	return "controller certificate: now checked against " + against
}
