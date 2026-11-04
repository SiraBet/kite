//go:build !windows

package installer

import "errors"

// Installation registers a Windows service and writes to the Windows
// registry, neither of which exists here. Present so the package builds,
// vets and is testable on Linux, which is where CI runs and where the
// Windows binaries are cross-compiled from.

func Install(o Options, report Progress) error {
	if err := o.validate(); err != nil {
		return err
	}
	return errors.New("the kite agent can only be installed on Windows")
}

func Uninstall(purge bool, report Progress) error {
	return errors.New("the kite agent can only be uninstalled on Windows")
}
