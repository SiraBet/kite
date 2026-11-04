// Package selfcfg reads configuration appended to the executable itself.
//
// The console can hand out a setup binary that already knows which
// controller it belongs to and carries a one-time enrollment token, so
// installing on a host is a double-click with nothing to type and
// nothing to mistype. When no such footer is present -- a plain download
// from the Fleet page -- the installer asks instead.
//
// The footer is appended after the end of the PE image. Windows ignores
// trailing bytes, so the binary still runs; the loader reads only what
// the headers describe.
//
//	... executable ...
//	<json payload>
//	<8 bytes: payload length, little-endian uint64>
//	<16 bytes: Magic>
//
// Deliberately simple, because the controller writes it in Python while
// this reads it in Go. Anything cleverer would need the same cleverness
// implemented twice and kept in step.
//
// Two consequences worth stating plainly. Appending invalidates an
// Authenticode signature, so a footer-carrying build cannot also be code
// signed -- sign the generic download and accept that per-host builds
// are unsigned, or drop the footer. And the token sits in the file in
// clear text: it is single-use and expires, so it is the same exposure
// as passing it on a command line, but the file should still be treated
// as a credential until it has been used.
package selfcfg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Magic is exactly 16 bytes and ends the file when a footer is present.
const Magic = "KITE-CONFIG-v01\n"

const (
	magicLen  = len(Magic)
	lengthLen = 8
	trailer   = magicLen + lengthLen
	// A sanity bound so a file whose last 16 bytes happen to match never
	// makes us try to allocate something absurd.
	maxPayload = 1 << 20
)

// Config is what the console bakes in. Every field is optional: a footer
// carrying only a controller URL is valid and means "ask for the rest".
type Config struct {
	ControllerURL string `json:"controller_url,omitempty"`
	Token         string `json:"token,omitempty"`
	Secret        string `json:"secret,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	Team          string `json:"team,omitempty"`
	Role          string `json:"role,omitempty"`
	Insecure      bool   `json:"insecure,omitempty"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	PollInterval  int    `json:"poll_interval,omitempty"`
}

// Read returns the footer on the running executable, if there is one.
func Read() (*Config, bool) {
	path, err := os.Executable()
	if err != nil {
		return nil, false
	}
	return ReadFile(path)
}

// ReadFile returns the footer on the named file, if there is one. A file
// without a footer is the normal case, not an error -- it is what a
// plain download looks like.
func ReadFile(path string) (*Config, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()

	size, err := file.Seek(0, io.SeekEnd)
	if err != nil || size < int64(trailer) {
		return nil, false
	}
	tail := make([]byte, trailer)
	if _, err := file.ReadAt(tail, size-int64(trailer)); err != nil {
		return nil, false
	}
	if !bytes.Equal(tail[lengthLen:], []byte(Magic)) {
		return nil, false
	}
	length := binary.LittleEndian.Uint64(tail[:lengthLen])
	if length == 0 || length > maxPayload || int64(length)+int64(trailer) > size {
		return nil, false
	}
	payload := make([]byte, length)
	if _, err := file.ReadAt(payload, size-int64(trailer)-int64(length)); err != nil {
		return nil, false
	}
	cfg := &Config{}
	if err := json.Unmarshal(payload, cfg); err != nil {
		return nil, false
	}
	return cfg, true
}

// Append writes src to dst with cfg attached. Used by the tests here and
// available to any Go caller; the controller does the same thing in
// Python when it builds a per-host download.
func Append(src, dst string, cfg Config) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Strip an existing footer rather than stacking a second one, so
	// re-generating from an already-generated binary is safe.
	if _, ok := ReadFile(src); ok {
		if trimmed, ok := strip(body); ok {
			body = trimmed
		}
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if len(payload) > maxPayload {
		return fmt.Errorf("embedded config is %d bytes, over the %d limit", len(payload), maxPayload)
	}
	out := make([]byte, 0, len(body)+len(payload)+trailer)
	out = append(out, body...)
	out = append(out, payload...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(payload)))
	out = append(out, Magic...)
	return os.WriteFile(dst, out, 0o755)
}

func strip(body []byte) ([]byte, bool) {
	if len(body) < trailer {
		return nil, false
	}
	tail := body[len(body)-trailer:]
	if !bytes.Equal(tail[lengthLen:], []byte(Magic)) {
		return nil, false
	}
	length := int(binary.LittleEndian.Uint64(tail[:lengthLen]))
	cut := len(body) - trailer - length
	if cut < 0 {
		return nil, false
	}
	return body[:cut], true
}
