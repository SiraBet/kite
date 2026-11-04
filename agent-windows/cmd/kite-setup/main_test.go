package main

import (
	"testing"

	"github.com/SiraBet/kite/agent-windows/internal/installer"
)

func presetLike(url, token string) installer.Options {
	return installer.Options{ControllerURL: url, Token: token}
}

// These switches are what deployment tooling is written against, so
// their exact shapes matter more than most parsing does: a flag silently
// ignored means an unattended install that enrols against the wrong
// controller, or not at all.
func TestParseArgsAcceptsWindowsInstallerConventions(t *testing.T) {
	args := parseArgs([]string{
		"/S", "/controller=https://kite.lab", "/token=abc123",
		`/dir="C:\Program Files\kite"`, "/insecure",
	})
	if !has(args, "s") {
		t.Error("/S not recognised as silent")
	}
	if args["controller"] != "https://kite.lab" {
		t.Errorf("controller = %q", args["controller"])
	}
	// A path with a space has to be quoted on the command line, and the
	// quotes must not survive into the path itself.
	if args["dir"] != `C:\Program Files\kite` {
		t.Errorf("dir = %q — quotes were not stripped", args["dir"])
	}
	if !has(args, "insecure") {
		t.Error("/insecure not recognised")
	}
}

func TestParseArgsIsCaseInsensitiveAndAcceptsDashes(t *testing.T) {
	// Windows switches are conventionally case-insensitive, and someone
	// coming from the Linux agent will reach for a dash.
	args := parseArgs([]string{"/UNINSTALL", "-token=abc"})
	if !has(args, "uninstall") {
		t.Error("/UNINSTALL not matched case-insensitively")
	}
	if args["token"] != "abc" {
		t.Errorf("token = %q — a dash-prefixed switch was not accepted", args["token"])
	}
}

// A deployment tool passing one flag we do not know about should not
// fail an otherwise valid install.
func TestParseArgsKeepsUnknownSwitches(t *testing.T) {
	args := parseArgs([]string{"/S", "/norestart", "/log=C:\\temp\\i.log"})
	if !has(args, "norestart") || args["log"] != `C:\temp\i.log` {
		t.Errorf("unknown switches were dropped: %#v", args)
	}
}

func TestCommandLineOverridesTheBakedInConfig(t *testing.T) {
	// A generated installer carries a controller and token; a switch on
	// the command line has to win, or a file generated for one host
	// could never be reused.
	opts := presetLike("https://baked.lab", "baked-token")
	applyArgs(&opts, parseArgs([]string{"/controller=https://override.lab", "/team=platform"}))

	if opts.ControllerURL != "https://override.lab" {
		t.Errorf("controller = %q", opts.ControllerURL)
	}
	if opts.Team != "platform" {
		t.Errorf("team = %q", opts.Team)
	}
	// Untouched by the command line, so the baked-in value survives.
	if opts.Token != "baked-token" {
		t.Errorf("token = %q — an unmentioned field was cleared", opts.Token)
	}
}

func TestEmptySwitchValueDoesNotClearAPresetField(t *testing.T) {
	opts := presetLike("https://baked.lab", "baked-token")
	applyArgs(&opts, parseArgs([]string{"/controller="}))
	if opts.ControllerURL != "https://baked.lab" {
		t.Errorf("an empty /controller= wiped the baked-in URL: %q", opts.ControllerURL)
	}
}

func TestPollIntervalMustBeANumber(t *testing.T) {
	opts := presetLike("https://baked.lab", "t")
	opts.PollInterval = 900
	applyArgs(&opts, parseArgs([]string{"/poll-interval=not-a-number"}))
	if opts.PollInterval != 900 {
		t.Errorf("a junk interval replaced a good one: %d", opts.PollInterval)
	}
	applyArgs(&opts, parseArgs([]string{"/poll-interval=300"}))
	if opts.PollInterval != 300 {
		t.Errorf("a valid interval was ignored: %d", opts.PollInterval)
	}
}
