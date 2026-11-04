//go:build windows

package console

import (
	"os"

	"golang.org/x/sys/windows"
)

// Package console reattaches a GUI-subsystem binary to the terminal that
// launched it.
//
// Both binaries here are linked for the GUI subsystem so that double-clicking it
// opens the status window without a console flashing up behind it. The
// cost is that it has no stdout at all -- run from a terminal, every CLI
// command would print into nothing.
//
// AttachConsole borrows the console of whatever launched us, so output
// lands in the terminal an operator typed into, and a double-click still
// gets no console because there is none to attach to.
var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// ATTACH_PARENT_PROCESS is (DWORD)-1. Not exported by x/sys/windows,
// which does not wrap AttachConsole at all.
const attachParentProcess = ^uintptr(0)

func Attach() {
	if ret, _, _ := procAttachConsole.Call(attachParentProcess); ret == 0 {
		return // launched from Explorer, not a terminal -- nothing to attach to
	}
	// Attaching alone is not enough: this process's handles still point
	// nowhere, so they have to be reopened onto the console we joined.
	if out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout, os.Stderr = out, out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
		os.Stdin = in
	}
}
