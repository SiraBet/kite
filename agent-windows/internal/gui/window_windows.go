//go:build windows

// The agent's status window: a real Win32 window, not a page served on
// loopback. Someone standing at a machine that is not getting patched
// wants to see why without being told to open a browser or a log file.
//
// It reports and nothing else. There is no "patch now" button: runs are
// scheduled and gated on the controller, and a button here would let
// somebody who has never heard of a maintenance window start one.
package gui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/SiraBet/kite/agent-windows/internal/agent"
)

// How often the window re-reads the agent's status. Two seconds is
// comfortably below what a person perceives as stale, and the read is
// from memory -- it costs nothing and never touches the controller.
const refreshInterval = 2 * time.Second

type window struct {
	main       *walk.MainWindow
	state      *walk.Label
	service    *walk.Label
	controller *walk.Label
	host       *walk.Label
	version    *walk.Label
	pending    *walk.Label
	log        *walk.TextEdit
}

// Run opens the window and blocks until it is closed.
func Run() error {
	w := &window{}
	err := MainWindow{
		AssignTo: &w.main,
		Title:    "kite agent",
		MinSize:  Size{Width: 620, Height: 460},
		Layout:   VBox{MarginsZero: false},
		MenuItems: []MenuItem{
			Menu{Text: "&File", Items: []MenuItem{
				Action{Text: "Open &log folder", OnTriggered: w.openLogFolder},
				Separator{},
				Action{Text: "E&xit", OnTriggered: func() { w.main.Close() }},
			}},
			Menu{Text: "&Help", Items: []MenuItem{
				Action{Text: "&About", OnTriggered: w.about},
			}},
		},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2, MarginsZero: false},
				Children: []Widget{
					Label{Text: "Status:"}, Label{AssignTo: &w.state, Text: "starting…"},
					Label{Text: "Service:"}, Label{AssignTo: &w.service, Text: "—"},
					Label{Text: "Controller:"}, Label{AssignTo: &w.controller, Text: "—"},
					Label{Text: "Host:"}, Label{AssignTo: &w.host, Text: "—"},
					Label{Text: "Agent:"}, Label{AssignTo: &w.version, Text: "—"},
					Label{Text: "Pending:"}, Label{AssignTo: &w.pending, Text: "—"},
				},
			},
			GroupBox{
				Title:  "Log",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo: &w.log,
						ReadOnly: true,
						VScroll:  true,
						// Fixed-width so timestamps and levels line up;
						// a wall of proportional text is unreadable at a
						// glance, which is the only way this gets read.
						Font: Font{Family: "Consolas", PointSize: 9},
					},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{Text: "Refresh", OnClicked: w.refresh},
					PushButton{Text: "Open log folder", OnClicked: w.openLogFolder},
					PushButton{Text: "Close", OnClicked: func() { w.main.Close() }},
				},
			},
		},
	}.Create()
	if err != nil {
		return err
	}

	w.refresh()
	go w.poll()
	w.main.Run()
	return nil
}

// poll drives the periodic refresh. Synchronize hands the update back to
// the UI thread -- walk widgets must not be touched from a goroutine,
// and doing so fails in ways that look like random corruption rather
// than an error.
func (w *window) poll() {
	for range time.Tick(refreshInterval) {
		if w.main == nil || w.main.IsDisposed() {
			return
		}
		w.main.Synchronize(w.refresh)
	}
}

func (w *window) refresh() {
	// Read what the service published, not this process's own state --
	// the window and the service are different processes and share no
	// memory.
	s, published := agent.ReadPersistedStatus()
	svcState := agent.QueryServiceState()

	text, colour := describeState(s, published, svcState)
	w.state.SetText(text)
	w.state.SetTextColor(colour)
	w.service.SetText(describeService(svcState))

	w.controller.SetText(orDash(s.Controller))
	if s.Enrolled {
		w.host.SetText(fmt.Sprintf("%s  (id %d)", orDash(s.Hostname), s.HostID))
	} else {
		w.host.SetText(orDash(s.Hostname))
	}

	version := s.Version
	if !s.LastPoll.IsZero() {
		version += "     Last poll: " + s.LastPoll.Format("15:04:05")
	}
	w.version.SetText(version)
	w.pending.SetText(describePending(s))

	// Windows line endings: a TextEdit renders a bare \n as a box.
	body := strings.Join(agent.TailLogLines(500), "\r\n")
	var b strings.Builder
	if body == "" {
		if agent.StateUnreadable() {
			b.WriteString("Can't read " + agent.LogPath() + " from this account. Restarting the kite-agent service fixes that (it opens the log to this machine's users).")
		} else {
			b.WriteString("No log yet at " + agent.LogPath())
		}
	} else {
		b.WriteString(body)
	}
	// Only rewrite when something changed, so the caret and any text the
	// user has selected to copy survive a refresh.
	if b.String() != w.log.Text() {
		w.log.SetText(b.String())
		// Move the caret to the end and scroll it into view, so the
		// newest lines show. SetTextSelection alone only moves the
		// caret; without ScrollToCaret the pane stays at the top and a
		// reader sees the oldest lines, which is the opposite of what
		// someone opening this window wants.
		w.log.SetTextSelection(len(b.String()), len(b.String()))
		w.log.ScrollToCaret()
	}
}

// describeState turns everything known into the one line someone reads
// first, ordered by what actually stops a host being patched. Every
// failure names what is wrong and, where there is one, what fixes it.
func describeState(s agent.Status, published bool, svcState agent.ServiceState) (string, walk.Color) {
	var (
		green = walk.RGB(0, 128, 0)
		red   = walk.RGB(180, 0, 0)
		amber = walk.RGB(170, 100, 0)
		grey  = walk.RGB(90, 90, 90)
	)
	switch {
	case svcState == agent.ServiceNotInstalled:
		return "Service not installed — run kite-agent-setup.exe", grey
	case !s.Enrolled && !published && agent.StateUnreadable():
		// The agent's files are there but locked to administrators -- an
		// agent that hasn't restarted since updating.
		return "Can't read the agent's status — restart the kite-agent service, or open this window as administrator", amber
	case !s.Enrolled && !published:
		return "Not enrolled — run the installer, or kite-agent enroll", grey
	case svcState == agent.ServiceStopped:
		// The most consequential state in this window: everything else
		// can look fine while the host quietly stops being patched.
		return "Service stopped — this host is NOT being patched", red
	case !published:
		return "Service running, waiting for its first poll", grey
	case s.CurrentStage != "":
		return fmt.Sprintf("Running %s (job %d)", s.CurrentStage, s.CurrentJob), amber
	case s.LastPoll.IsZero():
		return "Enrolled, waiting for the first poll", grey
	case !s.LastPollOK:
		return "Cannot reach the controller — " + s.LastPollErr, red
	default:
		return "Connected", green
	}
}

// describePending never renders an unknown count as a number. A host
// whose update search failed has an unknown number pending, not zero,
// and showing "0 updates" there is how an unpatched machine looks
// healthy.
func describePending(s agent.Status) string {
	if !s.Enrolled || (s.LastPoll.IsZero() && s.AssessErr == "") {
		return "—"
	}
	if !s.AssessOK {
		reason := s.AssessErr
		if reason == "" {
			reason = "the update search did not report a reason"
		}
		return "unknown — " + reason
	}
	if s.PendingCount == 1 {
		return "1 update"
	}
	return fmt.Sprintf("%d updates", s.PendingCount)
}

func describeService(state agent.ServiceState) string {
	switch state {
	case agent.ServiceRunning:
		return "running"
	case agent.ServiceStopped:
		return "stopped"
	case agent.ServiceNotInstalled:
		return "not installed"
	default:
		// Genuinely could not ask the Service Control Manager. Not the
		// same as "stopped", and reporting it as such would be a lie
		// this window exists to avoid.
		return "could not be determined"
	}
}

func (w *window) openLogFolder() {
	// Selects the log inside Explorer rather than opening it, so the
	// rotated agent.log.1 next to it is visible too.
	_ = exec.Command("explorer.exe", "/select,"+agent.LogPath()).Start()
}

func (w *window) about() {
	walk.MsgBox(w.main, "About kite agent",
		fmt.Sprintf("kite agent %s\n\nInstalled in %s\n\nThis window reports status only. "+
			"Patch runs are started and gated on the controller.",
			agent.AgentVersion, agent.InstallDir()),
		walk.MsgBoxIconInformation)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
