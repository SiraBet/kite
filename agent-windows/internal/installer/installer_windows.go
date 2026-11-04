//go:build windows

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/SiraBet/kite/agent-windows/internal/agent"
)

// Where Windows looks for the entry in Settings > Apps, and in the old
// Programs and Features. Registering here is what makes this a real
// installation rather than a copied file: it gives the machine's owner a
// documented way to remove it.
const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\kite-agent`

const startMenuDir = "kite"

// Install performs a full installation. Ordered so the reversible steps
// come first: nothing is registered with Windows until the agent is on
// disk and has successfully enrolled, because a half-installed service
// that cannot reach its controller is harder to explain than a failure
// that left nothing behind.
func Install(o Options, report Progress) error {
	if err := o.validate(); err != nil {
		return err
	}
	if !HasPayload() {
		return fmt.Errorf("this installer contains no agent binary and cannot install anything")
	}
	if o.ProgramDir == "" {
		o.ProgramDir = agent.ProgramDir()
	}
	// The service holds the executable open, so an upgrade has to stop
	// it before the file can be replaced. The agent it ran is kept until
	// the new one has enrolled: a re-run whose enrolment fails (a used
	// token, a typo) puts it back rather than leaving no agent at all.
	wasInstalled := agent.QueryServiceState() != agent.ServiceNotInstalled
	previous := ""
	if wasInstalled {
		report("Stopping the existing installation")
		if err := agent.UninstallService(); err != nil {
			return fmt.Errorf("could not remove the existing service: %w", err)
		}
		previous = filepath.Join(o.ProgramDir, "kite-agent.exe.previous")
		_ = os.Remove(previous)
		if raw, err := os.ReadFile(filepath.Join(o.ProgramDir, "kite-agent.exe")); err != nil ||
			os.WriteFile(previous, raw, 0o755) != nil {
			previous = ""
		}
	}
	putBack := func() {
		if previous == "" {
			return
		}
		report("Putting the previous agent back")
		target := filepath.Join(o.ProgramDir, "kite-agent.exe")
		_ = os.Remove(target)
		if err := os.Rename(previous, target); err == nil {
			if err := agent.RegisterService(); err != nil {
				report("  could not register it again: " + err.Error())
			}
		}
	}
	defer func() { _ = os.Remove(previous) }()

	report("Installing to " + o.ProgramDir)
	exePath, err := writeAgent(o.ProgramDir)
	if err != nil {
		putBack()
		return err
	}
	// The uninstaller has to survive the download being deleted, so this
	// binary copies itself in beside the agent.
	if err := copySelf(o.ProgramDir); err != nil {
		return fmt.Errorf("could not install the uninstaller: %w", err)
	}

	report("Enrolling with " + o.ControllerURL)
	if err := enroll(o); err != nil {
		// A new install leaves nothing registered: an agent that never
		// enrolled has no credential and would poll forever getting 401s.
		// A re-run gets its previous agent back, still enrolled (the
		// credential in agent.conf is only replaced by a successful enrol).
		_ = os.Remove(exePath)
		putBack()
		if previous != "" {
			return fmt.Errorf("enrollment failed, so the previous agent was put back and is running: %w", err)
		}
		return fmt.Errorf("enrollment failed: %w", err)
	}

	report("Registering the Windows service")
	if err := agent.RegisterService(); err != nil {
		return err
	}

	report("Registering with Apps & features")
	if err := writeUninstallEntry(o.ProgramDir); err != nil {
		// Not fatal. The agent is installed, enrolled and running; the
		// machine's owner simply has no entry in the list to remove it
		// from, which is worth saying rather than failing the install.
		report("  could not write the Apps & features entry: " + err.Error())
	}

	report("Creating Start menu shortcuts")
	if err := writeShortcuts(o.ProgramDir); err != nil {
		report("  could not create shortcuts: " + err.Error())
	}

	report("Done — the agent is running and will poll " + o.ControllerURL)
	return nil
}

// Uninstall removes the service, the registry entry, the shortcuts and
// the program directory. State under ProgramData is left alone unless
// purge is set: it holds this host's credential and the log of what was
// patched, and silently destroying that during an upgrade would be worse
// than leaving a directory behind.
func Uninstall(purge bool, report Progress) error {
	if agent.QueryServiceState() != agent.ServiceNotInstalled {
		report("Stopping and removing the service")
		if err := agent.UninstallService(); err != nil {
			return err
		}
	}

	report("Removing the Apps & features entry")
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); err != nil && !os.IsNotExist(err) {
		report("  " + err.Error())
	}

	report("Removing shortcuts")
	_ = os.RemoveAll(startMenuPath())

	report("Removing " + agent.ProgramDir())
	if err := os.RemoveAll(agent.ProgramDir()); err != nil {
		// Expected while this uninstaller is itself running from inside
		// that directory: Windows will not delete a running image.
		report("  some files are in use and will remain until reboot")
	}

	if purge {
		report("Removing " + agent.InstallDir() + " (credential and log)")
		_ = os.RemoveAll(agent.InstallDir())
	} else {
		report("Left in place: " + agent.InstallDir() + " (credential and log)")
	}
	report("Done")
	return nil
}

func copySelf(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, "kite-agent-setup.exe")
	if strings.EqualFold(self, target) {
		return nil // already running from the install directory
	}
	body, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return os.WriteFile(target, body, 0o755)
}

func writeUninstallEntry(dir string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	setup := filepath.Join(dir, "kite-agent-setup.exe")
	values := map[string]string{
		"DisplayName":     "kite agent",
		"DisplayVersion":  agent.AgentVersion,
		"Publisher":       "kite",
		"InstallLocation": dir,
		"DisplayIcon":     filepath.Join(dir, "kite-agent.exe"),
		"UninstallString": fmt.Sprintf("%q /uninstall", setup),
		// Offered separately so removing the agent does not have to mean
		// destroying the record of what it patched.
		"QuietUninstallString": fmt.Sprintf("%q /uninstall /S", setup),
	}
	for name, value := range values {
		if err := key.SetStringValue(name, value); err != nil {
			return err
		}
	}
	// Windows greys out Modify and Repair rather than offering buttons
	// that would do nothing.
	for _, name := range []string{"NoModify", "NoRepair"} {
		if err := key.SetDWordValue(name, 1); err != nil {
			return err
		}
	}
	return nil
}

func startMenuPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs`, startMenuDir)
}

// writeShortcuts creates the Start menu entries. A .lnk is a COM object
// (IShellLink) with no pure-Go writer, and this agent already depends on
// PowerShell for everything it does to Windows Update -- so it is built
// the same way rather than adding a cgo dependency for two files.
func writeShortcuts(dir string) error {
	menu := startMenuPath()
	if err := os.MkdirAll(menu, 0o755); err != nil {
		return err
	}
	shortcuts := []struct{ name, target, args, description string }{
		{"kite agent status.lnk", filepath.Join(dir, "kite-agent.exe"), "",
			"Show what the kite agent is doing"},
		{"Uninstall kite agent.lnk", filepath.Join(dir, "kite-agent-setup.exe"), "/uninstall",
			"Remove the kite agent"},
	}
	for _, s := range shortcuts {
		script := fmt.Sprintf(
			`$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%q);`+
				`$s.TargetPath=%q;$s.Arguments=%q;$s.WorkingDirectory=%q;$s.Description=%q;$s.Save()`,
			filepath.Join(menu, s.name), s.target, s.args, dir, s.description)
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", script)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", s.name, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
