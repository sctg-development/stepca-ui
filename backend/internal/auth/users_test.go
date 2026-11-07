package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sctg-development/stepca-ui/backend/internal/db"
)

func TestSyncUsersFile(t *testing.T) {
	dir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	h1, _ := HashPassword("one")
	h2, _ := HashPassword("two")
	f := filepath.Join(dir, "users.yaml")
	write := func(body string) {
		if err := os.WriteFile(f, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	write("users:\n  - {username: alice, passwordHash: '" + h1 + "', role: admin}\n  - {username: bob, passwordHash: '" + h2 + "'}\n")
	if n, err := SyncUsersFile(database, f); err != nil || n != 2 {
		t.Fatalf("sync: %d %v", n, err)
	}
	if u, _ := database.GetUserByUsername("bob"); u.Role != db.RoleViewer || !CheckPassword(u.PasswordHash, "two") {
		t.Fatal("bob must default to viewer with the given hash")
	}

	// the file stays the source of truth: change a role and a password
	write("users:\n  - {username: alice, passwordHash: '" + h2 + "', role: viewer}\n")
	if _, err := SyncUsersFile(database, f); err != nil {
		t.Fatal(err)
	}
	if u, _ := database.GetUserByUsername("alice"); u.Role != db.RoleViewer || !CheckPassword(u.PasswordHash, "two") {
		t.Fatal("alice must have been updated")
	}
	if n, _ := database.CountUsers(); n != 2 {
		t.Fatalf("accounts absent from the file must be kept, got %d", n)
	}

	write("users:\n  - {username: eve, passwordHash: 'not-a-bcrypt-hash', role: admin}\n")
	if _, err := SyncUsersFile(database, f); err == nil {
		t.Fatal("invalid bcrypt hash must be rejected")
	}
	write("users:\n  - {username: eve, passwordHash: '" + h1 + "', role: root}\n")
	if _, err := SyncUsersFile(database, f); err == nil {
		t.Fatal("invalid role must be rejected")
	}
}
