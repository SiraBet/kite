package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A controller over TLS with a certificate nothing trusts (httptest's
// own), publishing that certificate as its CA, as the default
// self-signed setup does.
func caController(t *testing.T, publish func(srv *httptest.Server) []byte) (*httptest.Server, *[]string) {
	t.Helper()
	var hits []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/download/ca.crt":
			if pemBytes := publish(srv); pemBytes != nil {
				w.Write(pemBytes)
				return
			}
			http.NotFound(w, r)
		case "/health":
			fmt.Fprint(w, `{"status":"ok"}`)
		case "/agent/enroll":
			fmt.Fprint(w, `{"host_id": 7, "agent_secret": "s3cret"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func ownCert(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func fingerprintOf(t *testing.T, raw []byte) string {
	cert, err := parseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	return CAFingerprint(cert)
}

func TestTheCAIsTrustedOnlyWithTheRightFingerprint(t *testing.T) {
	srv, _ := caController(t, ownCert)
	good := fingerprintOf(t, ownCert(srv))
	if _, err := FetchControllerCA(srv.URL, strings.ToUpper(good)); err != nil {
		t.Fatalf("right fingerprint refused: %v", err)
	}
	if _, err := FetchControllerCA(srv.URL, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "impersonating") {
		t.Fatalf("wrong fingerprint accepted: %v", err)
	}
}

func TestEnrolWithAFingerprintPinsTheCA(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	srv, _ := caController(t, ownCert)
	if err := Enroll(srv.URL, "tok", "", "host-a", "", "", false, fingerprintOf(t, ownCert(srv)), 900); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.VerifyTLS || cfg.CACert != CAPath() || cfg.AgentSecret != "s3cret" {
		t.Fatalf("config = %+v", cfg)
	}
	saved, _ := os.ReadFile(CAPath())
	if string(saved) != string(ownCert(srv)) {
		t.Fatal("the CA wasn't saved")
	}
	// and the client built from it checks the controller against that CA
	if err := NewClient(cfg).check(); err != nil {
		t.Fatalf("pinned client can't reach the controller: %v", err)
	}
}

func TestAnInsecureAgentPinsTheControllersCA(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	srv, hits := caController(t, ownCert)
	cfg := &Config{ControllerURL: srv.URL, HostID: 7, AgentSecret: "s", VerifyTLS: false}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, client: NewClient(cfg)}
	note := a.PinControllerCA()
	if !strings.Contains(note, "now checked against its CA") {
		t.Fatalf("note = %q", note)
	}
	if fmt.Sprint(*hits) != "[/download/ca.crt /health]" {
		t.Errorf("requests = %v, want the CA then a checked request before switching", *hits)
	}
	saved, _ := LoadConfig()
	if !saved.VerifyTLS || saved.CACert != CAPath() || !a.cfg.VerifyTLS {
		t.Fatalf("saved = %+v", saved)
	}
	if err := a.client.check(); err != nil {
		t.Fatalf("after pinning, the agent can't reach the controller: %v", err)
	}
	if note := a.PinControllerCA(); note != "" {
		t.Errorf("second call = %q, want nothing to do", note)
	}
}

func TestAFailedCheckLeavesTheAgentAsItWas(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	other := otherRoot(t) // not the root the controller's certificate comes from
	srv, _ := caController(t, func(*httptest.Server) []byte { return other })
	cfg := &Config{ControllerURL: srv.URL, HostID: 7, AgentSecret: "s", VerifyTLS: false}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, client: NewClient(cfg)}
	if note := a.PinControllerCA(); !strings.Contains(note, "still not checked") {
		t.Fatalf("note = %q", note)
	}
	saved, _ := LoadConfig()
	if saved.VerifyTLS || saved.CACert != "" || a.cfg.VerifyTLS {
		t.Fatalf("switched anyway: %+v", saved)
	}
	if _, err := os.Stat(CAPath()); !os.IsNotExist(err) {
		t.Error("a CA that didn't work was kept")
	}
}

func TestJunkInsteadOfACertificateChangesNothing(t *testing.T) {
	t.Setenv("KITE_AGENT_DIR", t.TempDir())
	srv, _ := caController(t, func(*httptest.Server) []byte { return []byte("<html>proxy login</html>") })
	cfg := &Config{ControllerURL: srv.URL, HostID: 7, AgentSecret: "s", VerifyTLS: false}
	a := &Agent{cfg: cfg, client: NewClient(cfg)}
	if note := a.PinControllerCA(); !strings.Contains(note, "isn't a certificate") || a.cfg.VerifyTLS {
		t.Fatalf("note = %q, verify = %v", note, a.cfg.VerifyTLS)
	}
}

// otherRoot is a self-signed CA that signed nothing the controller serves.
func otherRoot(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// check is a reachability probe through the client's own transport.
func (c *Client) check() error {
	resp, err := c.http.Get(c.base + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body map[string]any
	return json.NewDecoder(resp.Body).Decode(&body)
}
