package step

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile is one way of issuing certificates: a step-ca provisioner plus
// the credentials to obtain tokens for it, and the limits the UI enforces
// before even asking the CA (the provisioner's own claims stay authoritative).
type Profile struct {
	Name         string `yaml:"name" json:"name"`
	Label        string `yaml:"label" json:"label"`
	Provisioner  string `yaml:"provisioner" json:"-"`
	KeyFile      string `yaml:"keyFile" json:"-"`      // JWK private key (JSON), encrypted or not
	PasswordFile string `yaml:"passwordFile" json:"-"` // decrypts KeyFile / the CA-side encrypted key
	Password     string `yaml:"-" json:"-"`
	KeyType      string `yaml:"keyType" json:"key_type"` // EC (default), RSA, OKP
	KeySize      int    `yaml:"keySize" json:"key_size"`
	DefaultDays  int    `yaml:"defaultDays" json:"default_days"`
	MaxDays      int    `yaml:"maxDays" json:"max_days"`
}

type profilesFile struct {
	Profiles []Profile `yaml:"profiles"`
}

// LoadProfiles reads and validates the profiles file.
func LoadProfiles(path string) ([]Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profiles file: %w", err)
	}
	var f profilesFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse profiles file: %w", err)
	}
	if len(f.Profiles) == 0 {
		return nil, fmt.Errorf("profiles file %s defines no profile", path)
	}
	seen := map[string]bool{}
	for i := range f.Profiles {
		p := &f.Profiles[i]
		if p.Name == "" || p.Provisioner == "" {
			return nil, fmt.Errorf("profile #%d: name and provisioner are required", i+1)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("duplicate profile %q", p.Name)
		}
		seen[p.Name] = true
		if p.Label == "" {
			p.Label = p.Name
		}
		if p.DefaultDays <= 0 {
			p.DefaultDays = 90
		}
		if p.MaxDays <= 0 {
			p.MaxDays = 365
		}
		if p.DefaultDays > p.MaxDays {
			p.DefaultDays = p.MaxDays
		}
		if p.KeyFile == "" && p.PasswordFile == "" {
			return nil, fmt.Errorf("profile %q: keyFile or passwordFile is required", p.Name)
		}
		if p.PasswordFile != "" {
			pw, err := os.ReadFile(p.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("profile %q: %w", p.Name, err)
			}
			p.Password = string(pw)
		}
	}
	return f.Profiles, nil
}
