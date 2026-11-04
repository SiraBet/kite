package agent

import (
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Network is what the controller's inventory expects under "network" --
// the same shape the Linux agent sends (see the controller's
// schemas.AgentNetwork), so Topology and the machine page treat both alike.
type Network struct {
	OK             bool              `json:"ok"`
	Error          string            `json:"error"`
	Interfaces     []NetworkIface    `json:"interfaces"`
	DefaultGateway string            `json:"default_gateway"`
	Listening      []ListeningSocket `json:"listening"`
}

type NetworkIface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Kind      string   `json:"kind"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}

type ListeningSocket struct {
	Proto    string `json:"proto"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process"`
	Loopback bool   `json:"loopback"`
}

// The controller keeps at most this many of each; sending more is waste.
const (
	maxInterfaces = 64
	maxListening  = 256
)

var (
	ifaceNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.:@-]`)
	processUnsafe   = regexp.MustCompile(`[^A-Za-z0-9_.:/+@ -]`)
)

// DiscoverNetwork runs network.ps1. A failure is reported as "could not
// tell" (ok=false), never as a host with nothing open.
func DiscoverNetwork() Network {
	out, err := runScript("network.ps1", 60*time.Second)
	return parseNetwork(out, err)
}

func parseNetwork(out string, runErr error) Network {
	var raw Network
	line := lastJSONLine(out)
	if line == "" || json.Unmarshal([]byte(line), &raw) != nil {
		msg := "network.ps1 gave no readable result"
		if runErr != nil {
			msg += ": " + runErr.Error()
		}
		return Network{OK: false, Error: truncate(msg, 300), Interfaces: []NetworkIface{}, Listening: []ListeningSocket{}}
	}
	if !raw.OK {
		return Network{OK: false, Error: truncate(raw.Error, 300), Interfaces: []NetworkIface{}, Listening: []ListeningSocket{}}
	}
	return Network{
		OK:             true,
		Interfaces:     cleanInterfaces(raw.Interfaces),
		DefaultGateway: cleanIP(raw.DefaultGateway),
		Listening:      cleanListening(raw.Listening),
	}
}

// cleanInterfaces fits Windows' names to what the controller accepts:
// "vEthernet (Default Switch)" becomes "vEthernet__Default_Switch_", and
// "00-15-5D-01-02-03" becomes "00:15:5d:01:02:03".
func cleanInterfaces(in []NetworkIface) []NetworkIface {
	out := []NetworkIface{}
	for _, i := range in {
		name := ifaceNameUnsafe.ReplaceAllString(strings.TrimSpace(i.Name), "_")
		if name == "" {
			continue
		}
		if len(name) > 32 {
			name = name[:32]
		}
		addrs := []string{}
		for _, a := range i.Addresses {
			ip, n, err := net.ParseCIDR(stripZone(a))
			if err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				ones, _ := n.Mask.Size()
				addrs = append(addrs, ip.String()+"/"+itoa(ones))
			}
		}
		out = append(out, NetworkIface{Name: name, MAC: strings.ToLower(strings.ReplaceAll(i.MAC, "-", ":")),
			Kind: i.Kind, Up: i.Up, Addresses: addrs})
		if len(out) == maxInterfaces {
			break
		}
	}
	return out
}

// cleanListening normalises addresses, marks loopback-only sockets, drops
// duplicates (dual-stack shows some twice) and keeps TCP ahead of UDP when
// trimming, since a listening TCP port is the one people ask about.
func cleanListening(in []ListeningSocket) []ListeningSocket {
	seen := map[string]bool{}
	out := []ListeningSocket{}
	for _, s := range in {
		addr := cleanIP(s.Address)
		if (s.Proto != "tcp" && s.Proto != "udp") || addr == "" || s.Port <= 0 || s.Port > 65535 {
			continue
		}
		key := s.Proto + "|" + addr + "|" + itoa(s.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		proc := processUnsafe.ReplaceAllString(s.Process, "")
		if len(proc) > 64 {
			proc = proc[:64]
		}
		out = append(out, ListeningSocket{Proto: s.Proto, Address: addr, Port: s.Port, Process: proc,
			Loopback: net.ParseIP(addr).IsLoopback()})
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Proto != out[b].Proto {
			return out[a].Proto == "tcp"
		}
		return out[a].Port < out[b].Port
	})
	if len(out) > maxListening {
		out = out[:maxListening]
	}
	return out
}

func cleanIP(s string) string {
	ip := net.ParseIP(stripZone(strings.TrimSpace(s)))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// stripZone drops an IPv6 zone ("fe80::1%12/64" -> "fe80::1/64").
func stripZone(s string) string {
	if i := strings.Index(s, "%"); i >= 0 {
		rest := ""
		if j := strings.Index(s[i:], "/"); j >= 0 {
			rest = s[i+j:]
		}
		return s[:i] + rest
	}
	return s
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
