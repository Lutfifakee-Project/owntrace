package storage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestDatabaseFilePermissions proves §36: a created database file is
// owner-only regardless of the process umask.
func TestDatabaseFilePermissions(t *testing.T) {
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)
	path := filepath.Join(t.TempDir(), "perm.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("database permissions %s, want 0600", fi.Mode().Perm())
	}
}
