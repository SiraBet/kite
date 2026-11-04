//go:build !windows

// The window is Win32 and only builds on Windows. This stub exists so
// the rest of the agent still compiles, vets and tests on Linux, which
// is where CI runs and where the Windows binary is cross-compiled from.
package gui

import "errors"

func Run() error {
	return errors.New("the status window is only available on Windows")
}
