package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(&Config{ControllerURL: srv.URL, HostID: 7, VerifyTLS: true}), srv
}

// The controller answers an idle poll with a JSON null. That is "nothing
// to do", and it must not be confused with a poll that failed -- a host
// treating a network error as "no work" goes quietly idle while its jobs
// pile up on the controller.
func TestPollNextSeparatesNoWorkFromFailure(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "null")
		})
		instruction, _, err := client.PollNext("s3cret", 900)
		if err != nil {
			t.Fatalf("an idle poll reported an error: %v", err)
		}
		if instruction != nil {
			t.Fatalf("an idle poll produced an instruction: %+v", instruction)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"detail":"Invalid agent credential"}`)
		})
		_, _, err := client.PollNext("wrong", 900)
		if err == nil {
			t.Fatal("a 401 poll was reported as success")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("error does not name the status: %v", err)
		}
	})
}

func TestPollNextSendsCredentialAndVersion(t *testing.T) {
	var gotAuth, gotQuery, gotPath string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery, gotPath = r.Header.Get("Authorization"), r.URL.RawQuery, r.URL.Path
		io.WriteString(w, `{"job_id":42,"stage_name":"patch","severity_filter":"critical,important"}`)
	})
	instruction, _, err := client.PollNext("s3cret", 300)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/agent/7/jobs/next" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer s3cret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// The reported version is what drives the controller's self-update
	// header, so a poll that omits it silently disables that.
	if !strings.Contains(gotQuery, "agent_version="+AgentVersion) || !strings.Contains(gotQuery, "interval=300") {
		t.Errorf("query = %q", gotQuery)
	}
	if instruction.JobID != 42 || instruction.StageName != "patch" || instruction.SeverityFilter != "critical,important" {
		t.Errorf("instruction not parsed: %+v", instruction)
	}
}

func TestPollNextReadsSelfUpdateHeader(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SelfUpdateHeader, "0.9.9")
		io.WriteString(w, "null")
	})
	_, target, err := client.PollNext("s3cret", 900)
	if err != nil {
		t.Fatal(err)
	}
	if target != "0.9.9" {
		t.Errorf("self-update target = %q, want 0.9.9", target)
	}
}

// A nil Go slice marshals to JSON null, which the controller rejects.
// That happens exactly when the assessment failed and there is nothing to
// send -- so getting this wrong drops the updates_ok=false report, the
// one that says this host's pending count is unknown rather than zero.
func TestReportInventoryNeverSendsNullForUpdates(t *testing.T) {
	var body map[string]any
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("body was not JSON: %v", err)
		}
		if strings.Contains(string(raw), `"updates":null`) {
			t.Errorf("sent a JSON null for updates: %s", raw)
		}
	})
	if _, err := client.ReportInventory("s3cret", nil, nil, false, "WSUS unreachable", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, isList := body["updates"].([]any); !isList {
		t.Errorf("updates = %#v, want a list", body["updates"])
	}
	if _, isList := body["update_sources"].([]any); !isList {
		t.Errorf("update_sources = %#v, want a list", body["update_sources"])
	}
	if body["updates_ok"] != false {
		t.Errorf("updates_ok = %#v, want false", body["updates_ok"])
	}
	if body["updates_error"] != "WSUS unreachable" {
		t.Errorf("updates_error = %#v, want the reason to survive", body["updates_error"])
	}
}

func TestReportStageTruncatesOutput(t *testing.T) {
	var body map[string]string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		if r.URL.Path != "/agent/7/jobs/42/stages/patch/report" {
			t.Errorf("path = %q", r.URL.Path)
		}
	})
	huge := strings.Repeat("x", 9000) + "FAILED: the actual reason"
	if err := client.ReportStage("s3cret", 42, "patch", "failed", huge); err != nil {
		t.Fatal(err)
	}
	if len(body["output"]) > 8000 {
		t.Errorf("output not truncated: %d bytes", len(body["output"]))
	}
	if !strings.HasSuffix(body["output"], "FAILED: the actual reason") {
		t.Error("truncation dropped the end of the output, which is where the reason is")
	}
}

func TestReportStageSurfacesRejection(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"detail":"stage is not the current stage"}`)
	})
	err := client.ReportStage("s3cret", 42, "patch", "done", "ok")
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a rejected report was not surfaced: %v", err)
	}
}
