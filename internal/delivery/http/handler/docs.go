// Redoc UI for openapi.yaml (served at /docs).
package handler

import (
	"net/http"
)

// DocsRedoc serves a minimal HTML page that loads the OpenAPI spec.
func DocsRedoc(openapiPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Auth Service Docs</title>
  </head>
  <body>
    <redoc spec-url="` + openapiPath + `"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </body>
</html>`))
	}
}

