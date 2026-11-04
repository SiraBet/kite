package agent

import (
	"errors"
	"strings"
	"testing"
)

const sampleNetwork = `WARNING: ignore me
{"ok":true,"error":"","interfaces":[
 {"name":"Ethernet 2","mac":"00-15-5D-01-02-03","up":true,"kind":"","addresses":["10.20.30.40/24","fe80::1%12/64","2001:db8::5/64"]},
 {"name":"vEthernet (Default Switch)","mac":"00-15-5D-AA-BB-CC","up":true,"kind":"virtual","addresses":[]},
 {"name":"Loopback Pseudo-Interface 1","mac":"","up":true,"kind":"","addresses":["127.0.0.1/8"]}],
 "default_gateway":"10.20.30.1",
 "listening":[
  {"proto":"udp","address":"0.0.0.0","port":5353,"process":"svchost"},
  {"proto":"tcp","address":"0.0.0.0","port":3389,"process":"svchost"},
  {"proto":"tcp","address":"::","port":445,"process":"System"},
  {"proto":"tcp","address":"127.0.0.1","port":8080,"process":"my app <x>"},
  {"proto":"tcp","address":"0.0.0.0","port":3389,"process":"svchost"},
  {"proto":"tcp","address":"bogus","port":1,"process":"x"}]}`

func TestParseNetworkFitsWindowsToTheControllersShape(t *testing.T) {
	// network.ps1 prints one compressed JSON line, after whatever PowerShell warned about.
	head, body, _ := strings.Cut(sampleNetwork, "\n")
	n := parseNetwork(head+"\n"+strings.ReplaceAll(body, "\n", ""), nil)
	if !n.OK || n.DefaultGateway != "10.20.30.1" {
		t.Fatalf("ok=%v gw=%q", n.OK, n.DefaultGateway)
	}
	if len(n.Interfaces) != 3 {
		t.Fatalf("interfaces = %+v", n.Interfaces)
	}
	eth := n.Interfaces[0]
	if eth.Name != "Ethernet_2" || eth.MAC != "00:15:5d:01:02:03" {
		t.Errorf("eth = %+v", eth)
	}
	if len(eth.Addresses) != 2 || eth.Addresses[0] != "10.20.30.40/24" || eth.Addresses[1] != "2001:db8::5/64" {
		t.Errorf("addresses = %v (link-local must be dropped)", eth.Addresses)
	}
	if n.Interfaces[1].Name != "vEthernet__Default_Switch_" || n.Interfaces[1].Kind != "virtual" {
		t.Errorf("vEthernet = %+v", n.Interfaces[1])
	}
	if len(n.Interfaces[2].Addresses) != 0 {
		t.Errorf("loopback address kept: %v", n.Interfaces[2].Addresses)
	}

	l := n.Listening
	if len(l) != 4 {
		t.Fatalf("listening = %+v (duplicate and bogus must go)", l)
	}
	if l[0].Proto != "tcp" || l[0].Port != 445 || l[len(l)-1].Proto != "udp" {
		t.Errorf("order = %+v, want TCP by port then UDP", l)
	}
	for _, s := range l {
		if s.Port == 8080 && (!s.Loopback || s.Process != "my app x") {
			t.Errorf("8080 = %+v", s)
		}
		if s.Port == 3389 && s.Loopback {
			t.Errorf("3389 marked loopback")
		}
	}
}

func TestNetworkThatCouldNotBeReadIsNotEmpty(t *testing.T) {
	n := parseNetwork(`{"ok":false,"error":"Get-NetAdapter : Access denied"}`, nil)
	if n.OK || n.Error == "" || n.Interfaces == nil || n.Listening == nil {
		t.Errorf("%+v", n)
	}
	n = parseNetwork("", errors.New("timed out"))
	if n.OK || n.Error == "" {
		t.Errorf("%+v", n)
	}
}
