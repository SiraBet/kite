//go:build !windows

package agent

import "fmt"

// Stubs so the agent still builds and its testable parts still run on a
// developer's Linux machine. Service management is a Windows concept and
// there is nothing meaningful to do here.

func RunningAsService() bool { return false }

func RunService(cfg *Config) error {
	return fmt.Errorf("service mode is Windows-only; use `kite-agent run` here")
}

func InstallService() error {
	return fmt.Errorf("service installation is Windows-only")
}

func UninstallService() error {
	return fmt.Errorf("service removal is Windows-only")
}

// ServiceState mirrors the Windows type so the window's logic compiles
// and can be reasoned about off Windows. There is no SCM here, so the
// honest answer is that we cannot tell.
type ServiceState int

const (
	ServiceUnknown ServiceState = iota
	ServiceNotInstalled
	ServiceStopped
	ServiceRunning
)

func QueryServiceState() ServiceState { return ServiceUnknown }

// EnsureServiceRecovery is a Windows service setting; nothing to do elsewhere.
func EnsureServiceRecovery() {}

func restartServiceDetached() error {
	return fmt.Errorf("restarting the service is Windows-only")
}

// OpenUpPublicDir is a Windows ACL; nothing to do elsewhere.
func OpenUpPublicDir() {}
