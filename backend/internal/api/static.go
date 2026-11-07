package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// ServeStatic serves the exported (static) frontend from dir. Unknown paths
// that are not API routes fall back to 404.html; /_next assets are cached
// for a year (their names are content-hashed).
func ServeStatic(r *gin.Engine, dir string) {
	if _, err := os.Stat(dir); err != nil {
		return // API-only mode (development)
	}
	root, _ := filepath.Abs(dir)
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		clean := filepath.Clean("/" + c.Request.URL.Path)
		for _, cand := range []string{clean, clean + ".html", filepath.Join(clean, "index.html")} {
			full := filepath.Join(root, cand)
			if !strings.HasPrefix(full, root) {
				continue
			}
			if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
				if strings.HasPrefix(clean, "/_next/") {
					c.Header("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					c.Header("Cache-Control", "no-cache")
				}
				c.File(full)
				return
			}
		}
		if b, err := os.ReadFile(filepath.Join(root, "404.html")); err == nil {
			c.Data(http.StatusNotFound, "text/html; charset=utf-8", b)
			return
		}
		c.Status(http.StatusNotFound)
	})
}
