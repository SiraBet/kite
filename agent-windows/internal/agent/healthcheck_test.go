package agent

import (
	"strings"
	"testing"
)

// The script needs Windows to run, but the rules that keep it from
// failing healthy machines are worth pinning: a trigger-start service
// (Group Policy Client off a domain) or one that stopped cleanly is not a
// failure, and delayed-start services need the machine up a few minutes.
func TestHealthcheckOnlyFlagsServicesThatFailed(t *testing.T) {
	raw, err := scripts.ReadFile("scripts/healthcheck.ps1")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, rule := range []string{`\TriggerInfo"`, "$s.ExitCode -eq 0", "LastBootUpTime", "Start-Sleep"} {
		if !strings.Contains(body, rule) {
			t.Errorf("healthcheck.ps1 lost the rule containing %q", rule)
		}
	}
}
