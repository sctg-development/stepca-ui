package api

import (
	"github.com/sctg-development/stepca-ui/backend/internal/db"

	"github.com/gin-gonic/gin"
)

// SetupRoutes wires up the routes. authToken (RequireBearerToken) and user
// sessions (RequireSession/RequireRole) are layered, not alternatives: the
// bearer token is a shared secret between the frontend and backend
// containers (see API_AUTH_TOKEN in example.env), while sessions identify
// an actual logged-in person. /health is deliberately left open behind
// neither, so container/orchestrator healthchecks don't need either one.
func SetupRoutes(r *gin.Engine, handlers *Handlers, authToken string, proxy ProxyAuth) {
	// Health check (intentionally not behind auth)
	r.GET("/health", handlers.Health)

	api := r.Group("/api")
	api.Use(RequireBearerToken(authToken), RequireAjaxHeader())
	{
		// Login is the one endpoint that must work without a session
		// already -- it's how a session gets created in the first place.
		api.POST("/auth/login", handlers.Login)
		// Logout is safe to call with no session at all (it just no-ops),
		// so it doesn't need RequireSession either.
		api.POST("/auth/logout", handlers.Logout)

		// Everything else requires an actual logged-in account.
		loggedIn := api.Group("")
		loggedIn.Use(RequireSession(handlers.db, proxy))
		{
			loggedIn.GET("/auth/me", handlers.Me)

			// Read-only: any logged-in account, admin or viewer.
			loggedIn.GET("/certs", handlers.ListCertificates)
			loggedIn.GET("/certs/:id", handlers.GetCertificate)
			loggedIn.GET("/settings/ca", handlers.GetCASettings)
			loggedIn.GET("/profiles", handlers.ListProfiles)

			// Build identity (version, commit, build date) for the UI footer
			loggedIn.GET("/version", handlers.Version)

			// Mutating certificate operations and user management:
			// admin-only -- viewer accounts can look but not touch.
			admin := loggedIn.Group("")
			admin.Use(RequireRole(db.RoleAdmin))
			{
				admin.POST("/certs/issue", handlers.IssueCertificate)
				admin.POST("/certs/sign-csr", handlers.SignCSR)
				admin.POST("/certs/:id/renew", handlers.RenewCertificate)
				admin.POST("/certs/:id/revoke", handlers.RevokeCertificate)
				admin.POST("/certs/import", handlers.ImportCertificate)
				admin.POST("/sync", handlers.SyncNow)

				admin.GET("/users", handlers.ListUsers)
				admin.POST("/users", handlers.CreateUser)
				admin.PUT("/users/:id", handlers.UpdateUser)
				admin.DELETE("/users/:id", handlers.DeleteUser)
			}
		}
	}
}
