package nebulaboot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nebulaboot"
)

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
