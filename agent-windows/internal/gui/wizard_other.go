//go:build !windows

package gui

import (
	"errors"

	"github.com/SiraBet/kite/agent-windows/internal/installer"
)

// The installer's window is Win32. These stubs keep the setup binary
// building and vetting on Linux, which is where it is cross-compiled
// from and where CI runs.

func RunWizard(preset installer.Options) error {
	return errors.New("the installer is only available on Windows")
}

func RunUninstall(purge bool) error {
	return errors.New("the uninstaller is only available on Windows")
}
