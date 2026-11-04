package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const sampleSoftware = `{"ok":true,"error":"","items":[
 {"kind":"app","name":"Notepad++ (64-bit x64)","version":"8.6.9","publisher":"Notepad++ Team","arch":"x64"},
 {"kind":"app","name":"7-Zip 23.01","version":"23.01","publisher":"Igor Pavlov","arch":"x86"},
 {"kind":"kb","name":"KB5044273","version":"","publisher":"Microsoft","arch":""},
 {"kind":"app","name":"7-Zip 23.01","version":"23.01","publisher":"Igor Pavlov","arch":"x86"},
 {"kind":"app","name":"  ","version":"1"},
 {"kind":"os","name":"Windows 10 Pro","version":"10.0.19045.5011","publisher":"22H2","arch":""}]}`

func oneLine(s string) string { return strings.ReplaceAll(s, "\n", "") }

func TestSoftwareIsCleanedSortedAndDeduplicated(t *testing.T) {
	items, err := parseSoftware(oneLine(sampleSoftware), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("items = %+v (duplicate and nameless must go)", items)
	}
	if items[0].Name != "7-Zip 23.01" || items[2].Kind != "kb" || items[3].Kind != "os" {
		t.Errorf("order = %+v", items)
	}
	if items[3].Version != "10.0.19045.5011" {
		t.Errorf("os build = %q", items[3].Version)
	}
}

func TestUnreadableSoftwareIsAnErrorNotAnEmptyList(t *testing.T) {
	if _, err := parseSoftware(`{"ok":false,"error":"access denied"}`, nil); err == nil {
		t.Error("ok=false read as success")
	}
	if _, err := parseSoftware("", errors.New("timed out")); err == nil {
		t.Error("no output read as success")
	}
}

func TestTheFullListIsSentOnlyWhenItChanged(t *testing.T) {
	items, _ := parseSoftware(oneLine(sampleSoftware), nil)
	first := softwareReport(items, "")
	if first.Items == nil || len(first.Hash) != 64 {
		t.Fatalf("first report = %+v", first)
	}
	again := softwareReport(items, first.Hash)
	if again.Items != nil || again.Hash != first.Hash {
		t.Errorf("unchanged list resent: %+v", again)
	}
	raw, _ := json.Marshal(again)
	if strings.Contains(string(raw), "items") {
		t.Errorf("hash-only report carries items: %s", raw)
	}
}

func TestInventoryCarriesSoftwareAndReadsTheResendRequest(t *testing.T) {
	var body map[string]any
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		io.WriteString(w, `{"ok":true,"software_resend":true}`)
	})
	resend, err := client.ReportInventory("s", nil, nil, true, "", nil, &SoftwareReport{Hash: strings.Repeat("a", 64)})
	if err != nil || !resend {
		t.Fatalf("resend=%v err=%v", resend, err)
	}
	if sw, ok := body["software"].(map[string]any); !ok || sw["hash"] == "" {
		t.Errorf("software = %#v", body["software"])
	}
}
