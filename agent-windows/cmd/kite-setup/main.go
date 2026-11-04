// kite-agent-setup: the Windows agent installer.
//
// Double-clicked, it opens a wizard. Run with /S it installs silently
// from the switches given, which is what a software distribution tool
// needs. Both drive the same code in internal/installer, so an
// unattended install cannot drift from an interactive one.
//
// When the console generates this download for a specific host, the
// controller URL and a one-time token are appended to the file itself
// (see internal/selfcfg) and every field is already filled in.
//
//	kite-agent-setup.exe
//	kite-agent-setup.exe /S /controller=https://kite.lab /token=abc123
//	kite-agent-setup.exe /uninstall [/S] [/purge]
//
// Switches use the /name=value form Windows installers conventionally
// take, not Go's -name=value, because that is what the people running it
// will expect and what deployment tooling is written against.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/SiraBet/kite/agent-windows/internal/console"
	"github.com/SiraBet/kite/agent-windows/internal/gui"
	"github.com/SiraBet/kite/agent-windows/internal/installer"
	"github.com/SiraBet/kite/agent-windows/internal/selfcfg"
)

func main() {
	console.Attach()

	args := parseArgs(os.Args[1:])
	if _, wantsHelp := args["?"]; wantsHelp || has(args, "help") {
		usage()
		return
	}

	// Anything the console baked into this file, overridden by anything
	// given on the command line.
	opts := presetOptions()
	applyArgs(&opts, args)
	silent := has(args, "s")

	if has(args, "uninstall") {
		run(silent, func(report installer.Progress) error {
			return installer.Uninstall(has(args, "purge"), report)
		}, func() error { return gui.RunUninstall(has(args, "purge")) })
		return
	}

	if silent {
		run(true, func(report installer.Progress) error {
			return installer.Install(opts, report)
		}, nil)
		return
	}
	if err := gui.RunWizard(opts); err != nil {
		fatal(err)
	}
}

// run picks the silent or windowed path. Silent prints each step, so an
// unattended install still leaves a trail saying how far it got, and
// exits non-zero on failure so a deployment tool notices.
func run(silent bool, headless func(installer.Progress) error, windowed func() error) {
	if !silent && windowed != nil {
		if err := windowed(); err != nil {
			fatal(err)
		}
		return
	}
	if err := headless(func(step string) { fmt.Println(step) }); err != nil {
		fatal(err)
	}
}

func presetOptions() installer.Options {
	cfg, ok := selfcfg.Read()
	if !ok {
		return installer.Options{}
	}
	return installer.Options{
		ControllerURL: cfg.ControllerURL,
		Token:         cfg.Token,
		Secret:        cfg.Secret,
		Hostname:      cfg.Hostname,
		Team:          cfg.Team,
		Role:          cfg.Role,
		Insecure:      cfg.Insecure,
		CAFingerprint: cfg.CAFingerprint,
		PollInterval:  cfg.PollInterval,
	}
}

// parseArgs reads /name and /name=value into a lowercase map. Unknown
// switches are kept rather than rejected: a deployment tool passing one
// extra flag should not fail an otherwise valid install.
func parseArgs(argv []string) map[string]string {
	out := map[string]string{}
	for _, arg := range argv {
		trimmed := strings.TrimLeft(arg, "/-")
		if trimmed == "" {
			continue
		}
		name, value, found := strings.Cut(trimmed, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !found {
			out[name] = ""
			continue
		}
		out[name] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

func has(args map[string]string, name string) bool {
	_, ok := args[name]
	return ok
}

func applyArgs(o *installer.Options, args map[string]string) {
	set := func(name string, target *string) {
		if value, ok := args[name]; ok && value != "" {
			*target = value
		}
	}
	set("controller", &o.ControllerURL)
	set("token", &o.Token)
	set("secret", &o.Secret)
	set("hostname", &o.Hostname)
	set("team", &o.Team)
	set("role", &o.Role)
	set("dir", &o.ProgramDir)
	set("ca-fingerprint", &o.CAFingerprint)
	if has(args, "insecure") {
		o.Insecure = true
	}
	if value, ok := args["poll-interval"]; ok {
		if seconds, err := strconv.Atoi(value); err == nil {
			o.PollInterval = seconds
		}
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "kite-agent-setup: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Print(`kite agent installer

  kite-agent-setup.exe
      Open the installer window.

  kite-agent-setup.exe /S /controller=<url> /token=<token>
      Install without a window. /secret=<secret> works in place of
      /token when enrolling with the shared enrolment secret.

  kite-agent-setup.exe /uninstall [/S] [/purge]
      Remove the agent. /purge also deletes this host's credential and
      the log of what it patched; without it those are left in place.

Optional:  /hostname=<name>  /team=<team>  /role=<role>
           /dir=<path>  /poll-interval=<seconds>
           /ca-fingerprint=<sha256>  the controller's CA, from the console:
                       checked, then every call is checked against it
           /insecure   no certificate checks at all
`)
}
