package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SoftwareItem is one installed thing, in the controller's shape
// (schemas.AgentSoftwareItem): a Windows program (kind "app"), an
// installed update ("kb"), or the OS and its exact build ("os").
type SoftwareItem struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
	Publisher     string `json:"publisher"`
}

// SoftwareReport is what goes in the inventory: the full list only when
// it changed since the controller last took it, otherwise just the hash.
type SoftwareReport struct {
	Hash  string         `json:"hash"`
	Items []SoftwareItem `json:"items,omitempty"`
}

// CollectSoftware runs software.ps1. A failure returns an error and
// nothing is sent, rather than an empty list that would read as
// "nothing installed".
func CollectSoftware() ([]SoftwareItem, error) {
	out, err := runScript("software.ps1", 3*time.Minute)
	return parseSoftware(out, err)
}

func parseSoftware(out string, runErr error) ([]SoftwareItem, error) {
	var raw struct {
		OK    bool           `json:"ok"`
		Error string         `json:"error"`
		Items []SoftwareItem `json:"items"`
	}
	line := lastJSONLine(out)
	if line == "" || json.Unmarshal([]byte(line), &raw) != nil {
		if runErr != nil {
			return nil, fmt.Errorf("software.ps1: %w", runErr)
		}
		return nil, fmt.Errorf("software.ps1 gave no readable result")
	}
	if !raw.OK {
		return nil, fmt.Errorf("software.ps1: %s", raw.Error)
	}
	seen := map[string]bool{}
	items := []SoftwareItem{}
	for _, it := range raw.Items {
		it.Name = clip(strings.TrimSpace(it.Name), 200)
		it.Version = clip(strings.TrimSpace(it.Version), 120)
		it.Publisher = clip(strings.TrimSpace(it.Publisher), 200)
		key := it.Kind + "|" + it.Name + "|" + it.Version + "|" + it.Arch
		if it.Name == "" || seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, it)
	}
	// Sorted, so the same machine always hashes the same.
	sort.Slice(items, func(a, b int) bool {
		x, y := items[a], items[b]
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		if x.Arch != y.Arch {
			return x.Arch < y.Arch
		}
		return x.Version < y.Version
	})
	return items, nil
}

func softwareHash(items []SoftwareItem) string {
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// softwareReport is what this report carries, given the hash the
// controller last accepted ("" when it holds nothing of ours).
func softwareReport(items []SoftwareItem, sent string) *SoftwareReport {
	h := softwareHash(items)
	if h == sent {
		return &SoftwareReport{Hash: h}
	}
	return &SoftwareReport{Hash: h, Items: items}
}
