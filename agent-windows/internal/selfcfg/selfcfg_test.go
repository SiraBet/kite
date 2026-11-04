package selfcfg

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A plain download has no footer. That is the ordinary case, and it must
// read as "nothing embedded" rather than as an error or, worse, as junk
// config that sends the installer at the wrong controller.
func TestFileWithoutAFooterReadsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.exe")
	if err := os.WriteFile(path, []byte("MZ not really a binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg, ok := ReadFile(path); ok {
		t.Fatalf("found a footer that was never written: %+v", cfg)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "setup.exe")
	dst := filepath.Join(dir, "setup-web01.exe")
	body := []byte("MZ" + strings.Repeat("\x00", 4096))
	if err := os.WriteFile(src, body, 0o755); err != nil {
		t.Fatal(err)
	}

	want := Config{
		ControllerURL: "https://kite.lab", Token: "tok-123",
		Hostname: "web-01", Team: "platform", Role: "Web app server",
		PollInterval: 300,
	}
	if err := Append(src, dst, want); err != nil {
		t.Fatal(err)
	}

	got, ok := ReadFile(dst)
	if !ok {
		t.Fatal("footer not found on the file it was just written to")
	}
	if *got != want {
		t.Errorf("got %+v, want %+v", *got, want)
	}

	// The executable has to survive intact -- Windows ignores trailing
	// bytes, but only if the image itself is untouched.
	written, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(written[:len(body)]) != string(body) {
		t.Error("the original binary was modified, not appended to")
	}
}

// Regenerating from an already-generated binary must replace the footer,
// not stack a second one behind it.
func TestAppendReplacesAnExistingFooter(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "setup.exe")
	once := filepath.Join(dir, "once.exe")
	twice := filepath.Join(dir, "twice.exe")
	if err := os.WriteFile(src, []byte("MZ payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Append(src, once, Config{ControllerURL: "https://first", Token: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := Append(once, twice, Config{ControllerURL: "https://second", Token: "b"}); err != nil {
		t.Fatal(err)
	}

	got, ok := ReadFile(twice)
	if !ok {
		t.Fatal("no footer after the second append")
	}
	if got.ControllerURL != "https://second" || got.Token != "b" {
		t.Errorf("stale config survived: %+v", *got)
	}
	first, _ := os.ReadFile(once)
	second, _ := os.ReadFile(twice)
	if len(second) > len(first)+16 {
		t.Errorf("footers stacked: %d bytes vs %d", len(second), len(first))
	}
}

// A file whose last bytes happen to match the magic must not send us
// allocating a gigabyte or reading before the start of the file.
func TestCorruptFooterIsRejected(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"length longer than the file": append(
			binary.LittleEndian.AppendUint64([]byte("MZ"), 1<<19), []byte(Magic)...),
		"zero length": append(
			binary.LittleEndian.AppendUint64([]byte("MZ"), 0), []byte(Magic)...),
		"absurd length": append(
			binary.LittleEndian.AppendUint64([]byte("MZ"), 1<<40), []byte(Magic)...),
		"magic but the payload is not JSON": append(
			binary.LittleEndian.AppendUint64([]byte("MZnot json here"), 13), []byte(Magic)...),
		"file shorter than the trailer": []byte("MZ"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".exe")
			if err := os.WriteFile(path, body, 0o755); err != nil {
				t.Fatal(err)
			}
			if cfg, ok := ReadFile(path); ok {
				t.Errorf("accepted a corrupt footer: %+v", cfg)
			}
		})
	}
}

func TestMagicIsTheDocumentedSize(t *testing.T) {
	// The controller writes this footer in Python against the same
	// constant. If the size changes here and not there, every generated
	// installer silently loses its configuration.
	if len(Magic) != 16 {
		t.Fatalf("Magic is %d bytes, the format says 16", len(Magic))
	}
}
