package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	CAURL string
	// CARootFile is the CA root certificate on disk (mounted from a
	// ConfigMap). When set, the step CLI uses it directly instead of
	// downloading the root with CA_ROOT_FINGERPRINT on every operation.
	CARootFile        string
	CARootFingerprint string
	// ProfilesFile is a YAML file describing the issuance profiles (see
	// step.LoadProfiles). Without it a single "default" profile is built
	// from PROVISIONER_NAME / PROVISIONER_PASSWORD.
	ProfilesFile        string
	ProvisionerName     string
	ProvisionerPassword string
	DBPath              string
	Port                int
	StaticDir           string

	// APIAuthToken optionally requires `Authorization: Bearer <token>` on
	// every /api/* request. Off by default: with the UI served by the same
	// process (same origin) there is no separate frontend to share it with.
	APIAuthToken string
	// CORSAllowedOrigin is only needed when the frontend runs on another
	// origin (npm run dev). Empty = no CORS headers at all.
	CORSAllowedOrigin string

	// Local accounts. UsersFile is a YAML list of {username, passwordHash,
	// role} that is upserted into the database at every start: the file is
	// the source of truth for the accounts it names.
	UsersFile            string
	InitialAdminUsername string
	InitialAdminPassword string

	// Trusted-proxy authentication (oauth2-proxy in front of the UI). Only
	// enable when the UI is reachable exclusively through that proxy.
	TrustProxyAuth  bool
	ProxyUserHeader string
	AdminEmails     []string
	ViewerEmails    []string

	CookieSecure bool

	// cert-manager inventory (read-only, in-cluster).
	K8sSync         bool
	K8sIssuerName   string
	K8sSyncInterval time.Duration
}

func Load() *Config {
	port, _ := strconv.Atoi(getEnv("PORT", "8080"))
	interval, err := time.ParseDuration(getEnv("K8S_SYNC_INTERVAL", "5m"))
	if err != nil || interval < 30*time.Second {
		interval = 5 * time.Minute
	}

	return &Config{
		CAURL:                getEnv("CA_URL", ""),
		CARootFile:           getEnv("CA_ROOT_FILE", ""),
		CARootFingerprint:    getEnv("CA_ROOT_FINGERPRINT", ""),
		ProfilesFile:         getEnv("PROFILES_FILE", ""),
		ProvisionerName:      getEnv("PROVISIONER_NAME", "ui-admin"),
		ProvisionerPassword:  getEnv("PROVISIONER_PASSWORD", ""),
		DBPath:               getEnv("DB_PATH", "./data/certs.db"),
		Port:                 port,
		StaticDir:            getEnv("STATIC_DIR", "./web"),
		APIAuthToken:         getEnv("API_AUTH_TOKEN", ""),
		CORSAllowedOrigin:    getEnv("CORS_ALLOWED_ORIGIN", ""),
		UsersFile:            getEnv("USERS_FILE", ""),
		InitialAdminUsername: getEnv("INITIAL_ADMIN_USERNAME", ""),
		InitialAdminPassword: getEnv("INITIAL_ADMIN_PASSWORD", ""),
		TrustProxyAuth:       getBool("TRUST_PROXY_AUTH"),
		ProxyUserHeader:      getEnv("PROXY_USER_HEADER", "X-Forwarded-Email"),
		AdminEmails:          splitList(getEnv("ADMIN_EMAILS", "")),
		ViewerEmails:         splitList(getEnv("VIEWER_EMAILS", "")),
		CookieSecure:         getBool("COOKIE_SECURE"),
		K8sSync:              getBool("K8S_SYNC"),
		K8sIssuerName:        getEnv("K8S_ISSUER_NAME", "step-ca"),
		K8sSyncInterval:      interval,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBool(key string) bool {
	v, _ := strconv.ParseBool(os.Getenv(key))
	return v
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}
