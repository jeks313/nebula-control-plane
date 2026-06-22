package nebulaboot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nebulaboot"
)

// wintunArch mirrors nebulaboot.MaterializeWintun / nebula's tun_windows.go arch remap.
func wintunArch() string {
	if runtime.GOARCH == "386" {
		return "x86"
	}
	return runtime.GOARCH
}

func TestMaterializeWintunIntoDistTree(t *testing.T) {
	dir := t.TempDir()
	nebula := filepath.Join(dir, "sub", "nebula.exe") // missing parent dirs too
	dll := bytes.Repeat([]byte("W"), 2048)

	wrote, err := nebulaboot.MaterializeWintun(nebula, dll, nil)
	if err != nil || !wrote {
		t.Fatalf("materialize wintun: wrote=%v err=%v", wrote, err)
	}
	// nebula's checkWinTunExists loads <exedir>/dist/windows/wintun/bin/<arch>/wintun.dll
	// (slackhq/nebula overlay/tun_windows.go) — the dll MUST land at that exact path, not
	// flat beside nebula.exe.
	want := filepath.Join(dir, "sub", "dist", "windows", "wintun", "bin", wintunArch(), "wintun.dll")
	got, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(got, dll) {
		t.Fatalf("wintun.dll must land at %s: err=%v", want, err)
	}
}

func TestMaterializeWintunNilIsNoOp(t *testing.T) {
	dir := t.TempDir()
	// Empty data models a non-Windows / non-embed build (embeddedWintun() == nil).
	wrote, err := nebulaboot.MaterializeWintun(filepath.Join(dir, "nebula"), nil, nil)
	if err != nil || wrote {
		t.Fatalf("nil wintun must be a clean no-op: wrote=%v err=%v", wrote, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wintun.dll")); !os.IsNotExist(err) {
		t.Fatal("no-op must not create wintun.dll")
	}
}

func TestMaterializeWintunNoClobber(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dist", "windows", "wintun", "bin", wintunArch(), "wintun.dll")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := []byte("operator's pinned wintun.dll")
	if err := os.WriteFile(dest, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	wrote, err := nebulaboot.MaterializeWintun(filepath.Join(dir, "nebula.exe"), bytes.Repeat([]byte("X"), 2048), nil)
	if err != nil || wrote {
		t.Fatalf("must not clobber an existing wintun.dll: wrote=%v err=%v", wrote, err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, existing) {
		t.Fatal("existing wintun.dll must be left untouched")
	}
}

func TestMaterializeWritesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "nebula") // a missing parent dir too
	data := bytes.Repeat([]byte("N"), 4096)

	wrote, err := nebulaboot.Materialize(path, data, nil)
	if err != nil || !wrote {
		t.Fatalf("first materialize: wrote=%v err=%v", wrote, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("materialized content mismatch: err=%v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("materialized binary must be executable, got mode %v", fi.Mode())
	}
}

func TestMaterializeNoOpWhenPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula")
	existing := []byte("the operator's / Phase-1's binary")
	if err := os.WriteFile(path, existing, 0o755); err != nil {
		t.Fatal(err)
	}
	wrote, err := nebulaboot.Materialize(path, bytes.Repeat([]byte("E"), 4096), nil)
	if err != nil || wrote {
		t.Fatalf("must not clobber an existing binary: wrote=%v err=%v", wrote, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, existing) {
		t.Fatal("existing binary must be left untouched")
	}
}

func TestMaterializeNoEmbedIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula")
	// Empty data models a default build that embedded nothing.
	wrote, err := nebulaboot.Materialize(path, nil, nil)
	if err != nil || wrote {
		t.Fatalf("empty embed must be a clean no-op: wrote=%v err=%v", wrote, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no-op must not create a binary")
	}
}
