package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sctg-development/stepca-ui/backend/internal/api"
	"github.com/sctg-development/stepca-ui/backend/internal/auth"
	"github.com/sctg-development/stepca-ui/backend/internal/config"
	"github.com/sctg-development/stepca-ui/backend/internal/db"
	"github.com/sctg-development/stepca-ui/backend/internal/k8s"
	"github.com/sctg-development/stepca-ui/backend/internal/step"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database
	database, err := db.NewDatabase(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Accounts from the users file (values.yaml user/hash pairs)
	if cfg.UsersFile != "" {
		n, err := auth.SyncUsersFile(database, cfg.UsersFile)
		if err != nil {
			log.Fatalf("Failed to load users file: %v", err)
		}
		log.Printf("Synced %d account(s) from %s", n, cfg.UsersFile)
	}

	// Bootstrap admin from env, only against an empty users table
	if count, err := database.CountUsers(); err != nil {
		log.Printf("WARNING: failed to check for existing user accounts: %v", err)
	} else if count == 0 && !cfg.TrustProxyAuth {
		if cfg.InitialAdminUsername == "" || cfg.InitialAdminPassword == "" {
			log.Println("WARNING: no account exists and neither USERS_FILE, INITIAL_ADMIN_* nor TRUST_PROXY_AUTH is set -- nobody can log in.")
		} else if hash, err := auth.HashPassword(cfg.InitialAdminPassword); err != nil {
			log.Printf("WARNING: failed to hash initial admin password: %v", err)
		} else if err := database.CreateUser(&db.User{Username: cfg.InitialAdminUsername, PasswordHash: hash, Role: db.RoleAdmin}); err != nil {
			log.Printf("WARNING: failed to create initial admin account %q: %v", cfg.InitialAdminUsername, err)
		} else {
			log.Printf("Created initial admin account %q", cfg.InitialAdminUsername)
		}
	}

	// Issuance profiles
	var profiles []step.Profile
	if cfg.ProfilesFile != "" {
		var err error
		if profiles, err = step.LoadProfiles(cfg.ProfilesFile); err != nil {
			log.Fatalf("Failed to load profiles: %v", err)
		}
	} else {
		profiles = []step.Profile{{
			Name: "default", Label: "Default", Provisioner: cfg.ProvisionerName, Password: cfg.ProvisionerPassword,
			DefaultDays: 90, MaxDays: 365,
		}}
	}
	log.Printf("Profiles: %d, CA_URL=%s", len(profiles), cfg.CAURL)

	stepClient := step.NewStepClient(cfg.CAURL, cfg.CARootFile, cfg.CARootFingerprint, profiles)

	// cert-manager inventory
	var syncFn func() error
	if cfg.K8sSync {
		syncer, err := k8s.NewInCluster(database, cfg.K8sIssuerName)
		if err != nil {
			log.Printf("WARNING: cert-manager sync disabled: %v", err)
		} else {
			syncFn = syncer.Sync
			go func() {
				for {
					if err := syncer.Sync(); err != nil {
						log.Printf("cert-manager sync failed: %v", err)
					}
					time.Sleep(cfg.K8sSyncInterval)
				}
			}()
		}
	}

	proxy := api.ProxyAuth{Enabled: cfg.TrustProxyAuth, Header: cfg.ProxyUserHeader, Admins: cfg.AdminEmails, Viewers: cfg.ViewerEmails}
	if proxy.Enabled {
		log.Printf("Trusted-proxy authentication ON (header %s, %d admin(s), %d viewer(s))", proxy.Header, len(proxy.Admins), len(proxy.Viewers))
	}
	handlers := api.NewHandlers(database, stepClient, "acme-intranet", proxy, cfg.CookieSecure, syncFn)

	// Setup Gin router
	r := gin.Default()
	// client addresses are only used for logs: do not trust forwarded headers for them
	_ = r.SetTrustedProxies(nil)

	// CORS: restricted to CORS_ALLOWED_ORIGIN (defaults to the frontend's
	// own default address) instead of the previous "*", which let any
	// website's client-side JS call this API from a visitor's browser.
	r.Use(api.CORS(cfg.CORSAllowedOrigin))

	// Setup routes (authToken == "" leaves /api/* unauthenticated, matching
	// the previous behavior, but see the warning logged above)
	api.SetupRoutes(r, handlers, cfg.APIAuthToken, proxy)
	api.ServeStatic(r, cfg.StaticDir)

	// Start server
	log.Printf("Starting server on port %d", cfg.Port)
	if err := r.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
