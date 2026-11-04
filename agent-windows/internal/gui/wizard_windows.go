//go:build windows

// The installer's window.
//
// Two pages rather than a five-step wizard: everything an installation
// needs fits on one screen, and clicking Next past three pages of
// nothing is not an improvement. The second page is the progress log,
// which stays on screen afterwards so a failure can be read rather than
// disappearing with the window.
package gui

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/SiraBet/kite/agent-windows/internal/agent"
	"github.com/SiraBet/kite/agent-windows/internal/installer"
)

type wizard struct {
	main *walk.MainWindow

	settings *walk.Composite
	progress *walk.Composite

	controller *walk.LineEdit
	useToken   *walk.RadioButton
	credential *walk.LineEdit
	credLabel  *walk.Label
	hostname   *walk.LineEdit
	team       *walk.LineEdit
	dir        *walk.LineEdit
	insecure   *walk.CheckBox
	testResult *walk.Label

	installBtn *walk.PushButton
	closeBtn   *walk.PushButton
	log        *walk.TextEdit

	opts installer.Options
}

// RunWizard shows the installer. `preset` is whatever the console baked
// into this binary; empty fields simply mean the operator fills them in.
func RunWizard(preset installer.Options) error {
	w := &wizard{opts: preset}
	if w.opts.ProgramDir == "" {
		w.opts.ProgramDir = agent.ProgramDir()
	}

	err := MainWindow{
		AssignTo: &w.main,
		Title:    "Install kite agent",
		MinSize:  Size{Width: 560, Height: 430},
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				AssignTo: &w.settings,
				Layout:   Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Controller URL:"},
					LineEdit{AssignTo: &w.controller, Text: w.opts.ControllerURL,
						CueBanner: "https://kite.lab"},

					Label{Text: "Enrol with:"},
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							RadioButton{AssignTo: &w.useToken, Text: "One-time token",
								OnClicked: w.credentialKindChanged},
							RadioButton{Text: "Shared secret", OnClicked: w.credentialKindChanged},
							HSpacer{},
						},
					},

					Label{AssignTo: &w.credLabel, Text: "Token:"},
					LineEdit{AssignTo: &w.credential, Text: w.presetCredential(),
						CueBanner: "paste from the Fleet page"},

					Label{Text: "Hostname:"},
					LineEdit{AssignTo: &w.hostname, Text: w.opts.Hostname,
						CueBanner: "leave blank to use this machine's name"},

					Label{Text: "Team:"},
					LineEdit{AssignTo: &w.team, Text: w.opts.Team, CueBanner: "optional"},

					Label{Text: "Install to:"},
					LineEdit{AssignTo: &w.dir, Text: w.opts.ProgramDir},

					Label{Text: ""},
					CheckBox{AssignTo: &w.insecure, Checked: w.opts.Insecure,
						Text: "Skip TLS verification (controller uses a self-signed certificate)"},

					Label{Text: ""},
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{Text: "Test connection", OnClicked: w.testConnection},
							Label{AssignTo: &w.testResult, Text: ""},
							HSpacer{},
						},
					},
				},
			},
			Composite{
				AssignTo: &w.progress,
				Layout:   VBox{},
				Visible:  false,
				Children: []Widget{
					TextEdit{AssignTo: &w.log, ReadOnly: true, VScroll: true,
						Font: Font{Family: "Consolas", PointSize: 9}},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &w.installBtn, Text: "Install", OnClicked: w.install},
					PushButton{AssignTo: &w.closeBtn, Text: "Cancel",
						OnClicked: func() { w.main.Close() }},
				},
			},
		},
	}.Create()
	if err != nil {
		return err
	}
	w.useToken.SetChecked(w.opts.Secret == "")
	w.credentialKindChanged()
	w.main.Run()
	return nil
}

func (w *wizard) presetCredential() string {
	if w.opts.Token != "" {
		return w.opts.Token
	}
	return w.opts.Secret
}

func (w *wizard) credentialKindChanged() {
	if w.useToken.Checked() {
		w.credLabel.SetText("Token:")
	} else {
		w.credLabel.SetText("Secret:")
	}
}

func (w *wizard) collect() installer.Options {
	o := installer.Options{
		ControllerURL: strings.TrimSpace(w.controller.Text()),
		Hostname:      strings.TrimSpace(w.hostname.Text()),
		Team:          strings.TrimSpace(w.team.Text()),
		Role:          w.opts.Role,
		ProgramDir:    strings.TrimSpace(w.dir.Text()),
		Insecure:      w.insecure.Checked(),
		CAFingerprint: w.opts.CAFingerprint,
		PollInterval:  w.opts.PollInterval,
	}
	credential := strings.TrimSpace(w.credential.Text())
	if w.useToken.Checked() {
		o.Token = credential
	} else {
		o.Secret = credential
	}
	return o
}

func (w *wizard) testConnection() {
	url := strings.TrimSpace(w.controller.Text())
	if url == "" {
		w.testResult.SetText("enter a URL first")
		w.testResult.SetTextColor(walk.RGB(170, 100, 0))
		return
	}
	w.testResult.SetText("checking…")
	w.testResult.SetTextColor(walk.RGB(90, 90, 90))
	insecure := w.insecure.Checked()
	go func() {
		err := agent.CheckController(url, insecure, w.opts.CAFingerprint)
		w.main.Synchronize(func() {
			if err != nil {
				// The whole reason this button exists: a wrong URL or a
				// blocked port found now, rather than as a host that
				// silently never checks in.
				w.testResult.SetText("unreachable — " + err.Error())
				w.testResult.SetTextColor(walk.RGB(180, 0, 0))
				return
			}
			w.testResult.SetText("reachable")
			w.testResult.SetTextColor(walk.RGB(0, 128, 0))
		})
	}()
}

func (w *wizard) install() {
	opts := w.collect()
	if opts.ControllerURL == "" {
		walk.MsgBox(w.main, "Install kite agent",
			"A controller URL is required.", walk.MsgBoxIconWarning)
		return
	}
	if opts.Token == "" && opts.Secret == "" {
		walk.MsgBox(w.main, "Install kite agent",
			"Paste the one-time token from the Fleet page, or switch to the shared enrolment secret.",
			walk.MsgBoxIconWarning)
		return
	}

	w.settings.SetVisible(false)
	w.progress.SetVisible(true)
	w.installBtn.SetEnabled(false)
	w.closeBtn.SetText("Close")
	w.appendLog("Installing kite agent " + agent.AgentVersion)

	go func() {
		err := installer.Install(opts, func(step string) {
			w.main.Synchronize(func() { w.appendLog(step) })
		})
		w.main.Synchronize(func() {
			if err != nil {
				w.appendLog("")
				w.appendLog("FAILED: " + err.Error())
				// Re-enable so a typo can be corrected without starting
				// the installer over.
				w.installBtn.SetEnabled(true)
				w.settings.SetVisible(true)
				return
			}
			w.appendLog("")
			w.appendLog("The agent is installed and running.")
			w.appendLog("Status window: Start menu > kite > kite agent status")
		})
	}()
}

func (w *wizard) appendLog(line string) {
	w.log.AppendText(line + "\r\n")
}

// RunUninstall removes the installation, reporting into the same window.
func RunUninstall(purge bool) error {
	var mw *walk.MainWindow
	var log *walk.TextEdit
	err := MainWindow{
		AssignTo: &mw,
		Title:    "Uninstall kite agent",
		MinSize:  Size{Width: 520, Height: 320},
		Layout:   VBox{},
		Children: []Widget{
			TextEdit{AssignTo: &log, ReadOnly: true, VScroll: true,
				Font: Font{Family: "Consolas", PointSize: 9}},
			Composite{
				Layout:   HBox{},
				Children: []Widget{HSpacer{}, PushButton{Text: "Close", OnClicked: func() { mw.Close() }}},
			},
		},
	}.Create()
	if err != nil {
		return err
	}
	go func() {
		err := installer.Uninstall(purge, func(step string) {
			mw.Synchronize(func() { log.AppendText(step + "\r\n") })
		})
		mw.Synchronize(func() {
			if err != nil {
				log.AppendText(fmt.Sprintf("\r\nFAILED: %v\r\n", err))
			}
		})
	}()
	mw.Run()
	return nil
}
