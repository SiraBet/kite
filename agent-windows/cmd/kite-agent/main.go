// kite-agent: the Windows agent.
//
// Installed by kite-setup.exe, which is what an operator normally
// runs. This binary is the thing that gets installed: a Windows service
// that polls the controller for a stage, executes it, and reports back,
// plus the status window shown when somebody double-clicks it.
//
// The controller drives the pipeline; this has no opinion about what
// stage comes next, only how to run the one it is handed. That is the
// same contract the Linux agent follows, so a misbehaving host is
// diagnosed the same way whichever OS it runs.
//
//	kite-agent                 status window (what a double-click does)
//	kite-agent enroll ...      exchange a token for this host's credential
//	kite-agent install         register and start the Windows service
//	kite-agent uninstall       remove the service
//	kite-agent run             run the loop in this console
//	kite-agent once            poll a single time and exit
//	kite-agent status          print status as JSON
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/SiraBet/kite/agent-windows/internal/agent"
	"github.com/SiraBet/kite/agent-windows/internal/console"
	"github.com/SiraBet/kite/agent-windows/internal/gui"
)

func main() {
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	// Every path except the window wants to talk to a terminal.
	if command != "" && command != "ui" {
		console.Attach()
	}

	agent.OpenLog()

	// Started by the Service Control Manager rather than a person: no
	// arguments are passed, so this has to be detected rather than
	// signalled by a flag.
	if agent.RunningAsService() {
		cfg, err := agent.LoadConfig()
		if err != nil {
			agent.Error("service cannot start: %v", err)
			os.Exit(1)
		}
		if err := agent.RunService(cfg); err != nil {
			agent.Error("service failed: %v", err)
			os.Exit(1)
		}
		return
	}

	switch command {
	case "", "ui":
		// A double-click gets the status window, because somebody
		// double-clicking this wants to know whether it is working.
		agent.LoadStatusFromConfig()
		if err := gui.Run(); err != nil {
			fatal(err)
		}

	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		controller := fs.String("controller", "", "controller URL, e.g. https://kite.lab")
		token := fs.String("token", "", "one-time enrollment token from the Fleet page")
		secret := fs.String("secret", "", "shared enrollment secret (alternative to -token)")
		hostname := fs.String("hostname", "", "hostname to register as (defaults to this host's)")
		team := fs.String("team", "", "owning team")
		role := fs.String("role", "", "host role")
		interval := fs.Int("poll-interval", 900, "seconds between polls when idle")
		insecure := fs.Bool("insecure", false, "skip TLS verification altogether")
		caFingerprint := fs.String("ca-fingerprint", "", "SHA-256 of the controller's CA (console Enroll tab): checked, then pinned")
		_ = fs.Parse(os.Args[2:])
		if *controller == "" {
			fatal(fmt.Errorf("-controller is required"))
		}
		if err := agent.Enroll(*controller, *token, *secret, *hostname, *team, *role, *insecure, *caFingerprint, *interval); err != nil {
			fatal(err)
		}

	case "install":
		if err := agent.InstallService(); err != nil {
			fatal(err)
		}

	case "uninstall":
		if err := agent.UninstallService(); err != nil {
			fatal(err)
		}

	case "run":
		agent.NewAgent(mustLoadConfig()).Run(make(chan struct{}))

	case "once":
		if err := agent.PollOnce(mustLoadConfig()); err != nil {
			fatal(err)
		}

	case "status":
		agent.LoadStatusFromConfig()
		out, _ := json.MarshalIndent(agent.StatusSnapshot(), "", "  ")
		fmt.Println(string(out))

	case "version":
		fmt.Println(agent.AgentVersion)

	case "help", "-h", "--help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", command)
		usage()
		os.Exit(2)
	}
}

func mustLoadConfig() *agent.Config {
	cfg, err := agent.LoadConfig()
	if err != nil {
		fatal(err)
	}
	return cfg
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "kite-agent: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Print(`kite-agent ` + agent.AgentVersion + `

  kite-agent                 open the status window
  kite-agent enroll -controller <url> -token <token> [-ca-fingerprint <sha256> | -insecure]
  kite-agent install         register and start the Windows service
  kite-agent uninstall       remove the service
  kite-agent run             run the poll loop in this console
  kite-agent once            poll a single time and exit
  kite-agent status          print status as JSON
  kite-agent version

Install directory: ` + agent.InstallDir() + `
`)
}
