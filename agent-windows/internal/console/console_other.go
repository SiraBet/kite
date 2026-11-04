//go:build !windows

package console

// Package console is a no-op off Windows.
//
// Nothing to attach to: on Linux the binary is an ordinary console
// program and already has the streams it needs. Present so the agent
// builds and its behaviour can be exercised off Windows.
func Attach() {}
