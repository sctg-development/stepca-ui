package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func router(proxy ProxyAuth) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireAjaxHeader())
	g := r.Group("", RequireSession(nil, proxy))
	g.GET("/who", func(c *gin.Context) { c.JSON(200, gin.H{"u": CurrentUser(c).Username, "r": CurrentUser(c).Role}) })
	g.POST("/act", func(c *gin.Context) { c.Status(204) })
	return r
}

func do(r *gin.Engine, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestProxyAuth(t *testing.T) {
	r := router(ProxyAuth{Enabled: true, Header: "X-Forwarded-Email", Admins: []string{"root@example.org"}, Viewers: []string{"look@example.org"}})

	if w := do(r, "GET", "/who", map[string]string{"X-Forwarded-Email": "Root@Example.org"}); w.Code != 200 || w.Body.String() != `{"r":"admin","u":"root@example.org"}` {
		t.Fatalf("admin by header (case-insensitive): %d %s", w.Code, w.Body)
	}
	if w := do(r, "GET", "/who", map[string]string{"X-Forwarded-Email": "look@example.org"}); w.Code != 200 {
		t.Fatalf("viewer: %d", w.Code)
	}
	if w := do(r, "GET", "/who", map[string]string{"X-Forwarded-Email": "evil@example.org"}); w.Code != http.StatusForbidden {
		t.Fatalf("unlisted e-mail must be 403, got %d", w.Code)
	}
}

func TestAjaxHeaderRequiredForMutations(t *testing.T) {
	r := router(ProxyAuth{Enabled: true, Header: "X-Forwarded-Email", Admins: []string{"root@example.org"}})
	h := map[string]string{"X-Forwarded-Email": "root@example.org"}
	if w := do(r, "POST", "/act", h); w.Code != http.StatusForbidden {
		t.Fatalf("POST without X-Requested-With must be refused, got %d", w.Code)
	}
	h["X-Requested-With"] = "stepca-ui"
	if w := do(r, "POST", "/act", h); w.Code != 204 {
		t.Fatalf("POST with the header must pass, got %d", w.Code)
	}
}
