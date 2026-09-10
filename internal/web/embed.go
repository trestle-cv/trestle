package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
)

//go:embed public
var embedded embed.FS

func New(staticDir string) (http.Handler, error) {
	var root fs.FS
	if staticDir == "" {
		var err error
		root, err = fs.Sub(embedded, "public")
		if err != nil {
			return nil, err
		}
	} else {
		info, err := os.Stat(staticDir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errors.New("static override is not a directory")
		}
		root = os.DirFS(staticDir)
	}
	hash := sha256.New()
	for _, name := range []string{"assets/css/style.css", "assets/js/script.js", "assets/css/manage.css", "assets/css/launcher.css", "assets/js/manage.js", "assets/js/launcher.js"} {
		data, err := fs.ReadFile(root, name)
		if err != nil {
			continue
		}
		_, _ = hash.Write(data)
	}
	version := hex.EncodeToString(hash.Sum(nil))[:12]
	return handler{root: root, assetVersion: version}, nil
}

type handler struct {
	root         fs.FS
	assetVersion string
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "app" || strings.HasPrefix(name, "app/") {
		name = strings.TrimPrefix(strings.TrimPrefix(name, "app"), "/")
	}
	if name == "." || name == "" {
		name = "index.html"
	}
	data, err := fs.ReadFile(h.root, name)
	if err != nil && !strings.Contains(path.Base(name), ".") {
		data, err = fs.ReadFile(h.root, "index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if strings.HasSuffix(name, ".html") || name == "index.html" {
		data = []byte(strings.ReplaceAll(string(data), "__TRESTLE_ASSET_VERSION__", h.assetVersion))
		w.Header().Set("Cache-Control", "no-cache")
	} else if r.URL.Query().Get("v") == h.assetVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	_, _ = w.Write(data)
}
