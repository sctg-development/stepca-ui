package auth

import (
	"fmt"
	"os"

	"github.com/sctg-development/stepca-ui/backend/internal/db"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type fileUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"passwordHash"`
	Role         string `yaml:"role"`
}

type usersFile struct {
	Users []fileUser `yaml:"users"`
}

// SyncUsersFile upserts the accounts listed in a YAML file ({username,
// passwordHash (bcrypt), role}) into the database. The file is the source of
// truth for the accounts it names: password and role are overwritten at each
// start. Accounts not in the file are left alone. Returns how many were synced.
func SyncUsersFile(database *db.Database, path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read users file: %w", err)
	}
	var f usersFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("parse users file: %w", err)
	}
	n := 0
	for _, u := range f.Users {
		role := db.Role(u.Role)
		if role == "" {
			role = db.RoleViewer
		}
		if u.Username == "" || (role != db.RoleAdmin && role != db.RoleViewer) {
			return n, fmt.Errorf("invalid user entry %q (role must be admin or viewer)", u.Username)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return n, fmt.Errorf("user %q: passwordHash is not a valid bcrypt hash", u.Username)
		}
		existing, err := database.GetUserByUsername(u.Username)
		if err != nil || existing.ID == 0 {
			if err := database.CreateUser(&db.User{Username: u.Username, PasswordHash: u.PasswordHash, Role: role}); err != nil {
				return n, err
			}
		} else {
			changed := existing.PasswordHash != u.PasswordHash || existing.Role != role
			existing.PasswordHash = u.PasswordHash
			existing.Role = role
			if err := database.UpdateUser(existing); err != nil {
				return n, err
			}
			if changed {
				_ = database.DeleteSessionsForUser(existing.ID)
			}
		}
		n++
	}
	return n, nil
}
