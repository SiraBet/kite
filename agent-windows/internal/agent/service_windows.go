//go:build windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "kite-agent"

type windowsService struct{ cfg *Config }

// Execute is the Service Control Manager's entry point. Stop and shutdown
// close the channel the poll loop watches and end any script a stage is
// running (StopRunningWork), then wait -- telling the SCM so -- for the
// loop to report that stage and return, rather than exiting under it and
// leaving PowerShell running orphaned with the stage never reported.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	stop, done := make(chan struct{}), make(chan struct{})
	go func() { NewAgent(s.cfg).Run(stop); close(done) }()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			Info("service stop requested")
			close(stop)
			StopRunningWork()
			for i := uint32(1); i <= 12; i++ {
				changes <- svc.Status{State: svc.StopPending, CheckPoint: i, WaitHint: 6000}
				select {
				case <-done:
					return false, 0
				case <-time.After(5 * time.Second):
				}
			}
			Warn("the poll loop didn't finish within a minute of the stop; exiting anyway")
			return false, 0
		}
	}
	return false, 0
}

// RunningAsService reports whether the SCM started us, as opposed to a
// person running the binary from a console.
func RunningAsService() bool {
	isService, err := svc.IsWindowsService()
	return err == nil && isService
}

func RunService(cfg *Config) error {
	LockDownStateDir() // on every start, so earlier installs (and a tampered folder) are put right
	OpenUpPublicDir()  // and the status folder readable, on every start
	return svc.Run(serviceName, &windowsService{cfg: cfg})
}

// InstallService copies this binary into place and registers it. Used by
// `kite-agent install` -- the wizard calls RegisterService directly,
// having already written the binary it wants registered.
func InstallService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ProgramDir(), 0o755); err != nil {
		return err
	}
	if !samePath(exe, AgentExePath()) {
		if err := copyFile(exe, AgentExePath()); err != nil {
			return fmt.Errorf("could not copy the agent into %s: %w", ProgramDir(), err)
		}
	}
	if err := RegisterService(); err != nil {
		return err
	}
	fmt.Printf("Service %q installed and started.\nLog: %s\nStatus window: kite-agent ui\n",
		serviceName, LogPath())
	return nil
}

// LockDownStateDir restricts the directory holding this host's
// credential and the log of everything the agent has done to SYSTEM and
// Administrators.
func LockDownStateDir() {
	if err := lockDown(InstallDir()); err != nil {
		Error("could not restrict %s to SYSTEM and Administrators: %v", InstallDir(), err)
	}
}

// lockDown makes dir owned by Administrators and readable and writable
// by SYSTEM and Administrators alone -- including when someone else
// created it first (anyone can create a folder under ProgramData) and gave
// themselves access: ownership is taken, and their explicit entries go
// with /reset before inheritance is cut. SIDs, not names, so it works on
// any Windows language. The agent runs scripts from here as SYSTEM.
func lockDown(dir string) error {
	steps := [][]string{
		{dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"},
		{dir, "/reset", "/T", "/C", "/Q"},
		{dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"},
	}
	for _, args := range steps {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("icacls %s: %v: %s", strings.Join(args[1:], " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// EnsureServiceRecovery has Windows restart the service a minute after it
// stops unexpectedly. Without it, an agent that crashed -- a bad update
// before checkNewBinary could put the previous one back -- stayed stopped
// until someone noticed. Set at every start, so installs from before this
// get it too; best effort.
func EnsureServiceRecovery() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return
	}
	defer service.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Minute}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		Warn("could not set the service to restart after a failure: %v", err)
	}
}

// restartServiceDetached asks for this service to be restarted by a
// process that outlives it: the service can't start itself again once it
// has stopped. The short wait lets the poll loop finish reporting first.
func restartServiceDetached() error {
	cmd := exec.Command("cmd.exe", "/c",
		"ping -n 4 127.0.0.1 >nul & net stop "+serviceName+" & net start "+serviceName)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	return cmd.Start()
}

// OpenUpPublicDir lets the host's users read PublicDir (status.json and
// the log) so the status window, which runs unelevated, can show them.
// Read only; agent.conf stays in the locked parent. SIDs rather than
// names, so it works on non-English Windows: S-1-5-32-545 is BUILTIN\Users.
func OpenUpPublicDir() {
	_ = os.MkdirAll(PublicDir(), 0o755)
	_ = exec.Command("icacls", PublicDir(), "/grant", "*S-1-5-32-545:(OI)(CI)RX").Run()
}

// RegisterService registers the already-installed binary to start at
// boot as LocalSystem, which is what patching requires.
func RegisterService() error {
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return err
	}
	LockDownStateDir()
	OpenUpPublicDir()
	target := AgentExePath()

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not talk to the service manager (run this from an elevated prompt): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		return fmt.Errorf("the %s service already exists. Run `kite-agent uninstall` first", serviceName)
	}
	service, err := m.CreateService(serviceName, target, mgr.Config{
		DisplayName:  "kite agent",
		Description:  "Polls the kite controller and applies Windows updates on its instruction.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return fmt.Errorf("could not create the service: %w", err)
	}
	defer service.Close()

	if err := service.Start(); err != nil {
		return fmt.Errorf("service registered but would not start: %w", err)
	}
	return nil
}

func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not talk to the service manager (elevated prompt required): %w", err)
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the %s service is not installed", serviceName)
	}
	defer service.Close()

	_, _ = service.Control(svc.Stop)
	// The SCM marks a service stopped asynchronously; deleting one that
	// is still running leaves it pending until the next reboot.
	for i := 0; i < 20; i++ {
		if s, err := service.Query(); err == nil && s.State == svc.Stopped {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("could not remove the service: %w", err)
	}
	fmt.Printf("Service %q removed. %s was left in place (config and log).\n", serviceName, InstallDir())
	return nil
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && aa == bb
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// ServiceState describes what the Service Control Manager says about the
// agent service. The status window runs as an ordinary user, so this
// deliberately opens the SCM with only the rights needed to read --
// mgr.Connect asks for full access and would fail without admin, which
// would report "cannot tell" on the most common question there is.
type ServiceState int

const (
	ServiceUnknown ServiceState = iota
	ServiceNotInstalled
	ServiceStopped
	ServiceRunning
)

func QueryServiceState() ServiceState {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ServiceUnknown
	}
	defer windows.CloseServiceHandle(scm)

	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return ServiceUnknown
	}
	handle, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		// Anything else here (access denied, SCM unavailable) is not the
		// same as "not installed", and saying it is would send someone
		// reinstalling an agent that is already there.
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return ServiceNotInstalled
		}
		return ServiceUnknown
	}
	defer windows.CloseServiceHandle(handle)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(handle, &status); err != nil {
		return ServiceUnknown
	}
	if status.CurrentState == windows.SERVICE_RUNNING {
		return ServiceRunning
	}
	return ServiceStopped
}
