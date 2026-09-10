package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/trestle-cv/trestle/internal/buildinfo"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/requestmeta"
)

type Options struct {
	TrustedProxies            []netip.Prefix
	Root, Manage, LauncherAPI http.Handler
}

type Server struct {
	logger  *slog.Logger
	ready   atomic.Bool
	dbCheck func(context.Context) error
	ids     atomic.Uint64
	handler http.Handler
}

func New(logger *slog.Logger, dashboard ...http.Handler) *Server {
	return newServer(logger, first(dashboard), nil, nil, Options{})
}

func NewWithAdmin(logger *slog.Logger, dashboard, admin http.Handler) *Server {
	return newServer(logger, dashboard, nil, admin, Options{})
}
func NewWithHandlers(logger *slog.Logger, dashboard, api, admin http.Handler) *Server {
	return newServer(logger, dashboard, api, admin, Options{})
}
func NewWithOptions(logger *slog.Logger, dashboard, api, admin http.Handler, options Options) *Server {
	return newServer(logger, dashboard, api, admin, options)
}
func first(handlers []http.Handler) http.Handler {
	if len(handlers) == 0 {
		return nil
	}
	return handlers[0]
}
func newServer(logger *slog.Logger, dashboard, api, admin http.Handler, options Options) *Server {
	s := &Server{logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /system/health", s.health)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /system/ready", s.readiness)
	mux.HandleFunc("GET /system/version", s.version)
	if admin != nil {
		mux.Handle("/admin/v1/", admin)
	}
	if api != nil {
		mux.Handle("/api/v1/", api)
	}
	if options.LauncherAPI != nil {
		mux.Handle("/api/launcher/", options.LauncherAPI)
	}
	if options.Manage != nil {
		mux.Handle("/manage/", options.Manage)
		mux.HandleFunc("GET /manage", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/manage/", http.StatusPermanentRedirect)
		})
	}
	if dashboard != nil {
		if options.Root == nil {
			mux.Handle("/", dashboard)
		} else {
			mux.Handle("/assets/", dashboard)
			mux.Handle("/app/", dashboard)
			mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/app/", http.StatusPermanentRedirect)
			})
		}
	}
	if options.Root != nil {
		mux.Handle("/", options.Root)
	}
	s.handler = s.proxyContext(options.TrustedProxies, s.requestContext(mux))
	return s
}

func (s *Server) Handler() http.Handler { return s.handler }
func (s *Server) SetReady(value bool)   { s.ready.Store(value) }

// SetDatabaseCheck wires a liveness probe for the configured database into
// readiness, so orchestration can distinguish a starting/unready process from
// a ready process whose database became unavailable (degraded) and later
// recovered. health remains pure process liveness.
func (s *Server) SetDatabaseCheck(check func(context.Context) error) {
	s.dbCheck = check
}

func (s *Server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		id := "req_" + strconv.FormatUint(s.ids.Add(1), 36)
		w.Header().Set("X-Request-ID", id)
		r.Header.Set("X-Trestle-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data:; connect-src 'self'; style-src 'self'; script-src 'self'")
		next.ServeHTTP(w, r)
		s.logger.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path, "client_ip", requestmeta.ClientIP(r), "scheme", requestmeta.Scheme(r), "duration_ms", time.Since(started).Milliseconds())
	})
}

func (s *Server) proxyContext(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := parseRemoteIP(r.RemoteAddr)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		client := peer.String()
		if trustedIP(peer, trusted) {
			if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
				scheme = forwarded
			}
			if forwarded := forwardedClient(r.Header.Get("X-Forwarded-For"), peer, trusted); forwarded.IsValid() {
				client = forwarded.String()
			}
		}
		r.Header.Del("Forwarded")
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-Proto")
		next.ServeHTTP(w, requestmeta.With(r, scheme, client))
	})
}

func parseRemoteIP(value string) netip.Addr {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		value = host
	}
	address, _ := netip.ParseAddr(strings.Trim(value, "[]"))
	return address.Unmap()
}
func trustedIP(address netip.Addr, trusted []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	for _, prefix := range trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
func forwardedClient(header string, peer netip.Addr, trusted []netip.Prefix) netip.Addr {
	chain := strings.Split(header, ",")
	addresses := make([]netip.Addr, 0, len(chain)+1)
	for _, raw := range chain {
		if address, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			addresses = append(addresses, address.Unmap())
		}
	}
	addresses = append(addresses, peer)
	for i := len(addresses) - 1; i >= 0; i-- {
		if !trustedIP(addresses[i], trusted) {
			return addresses[i]
		}
	}
	return netip.Addr{}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, httperr.New("not_ready", "The service is not ready.", w.Header().Get("X-Request-ID")))
		return
	}
	if s.dbCheck != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.dbCheck(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, httperr.New("database_unavailable", "The database is unavailable.", w.Header().Get("X-Request-ID")))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, buildinfo.Current())
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
