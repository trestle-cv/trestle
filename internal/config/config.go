package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen                  string
	DataDir                 string
	ShutdownTimeout         time.Duration
	LogLevel                string
	StaticDir               string
	StorageBackend          string
	S3Endpoint              string
	S3Region                string
	S3Bucket                string
	S3AccessKey             string
	S3SecretKey             string
	AWSRegion               string
	AWSAccessKey            string
	AWSSecretKey            string
	TrustedProxies          []netip.Prefix
	ReadHeaderTimeout       time.Duration
	ReadTimeout             time.Duration
	IdleTimeout             time.Duration
	MaxHeaderBytes          int
	DatabaseProvider        string
	DatabaseURL             string
	DatabaseMaxOpen         int
	DatabaseMaxIdle         int
	DatabaseConnectTimeout  time.Duration
	DatabaseConnMaxLifetime time.Duration
	DatabaseExplicit        bool
	DatabaseConfigured      bool
	Replication             ReplicationConfig
}

type ReplicationConfig struct {
	Enabled           bool
	NodeID            string
	Bootstrap         bool
	Listen            string
	TLSCert           string
	TLSKey            string
	TLSCA             string
	InsecurePlaintext bool
}

func Defaults() Config {
	return Config{Listen: "127.0.0.1:7333", DataDir: "./data", ShutdownTimeout: 10 * time.Second, LogLevel: "info", StorageBackend: "local", S3Region: "us-east-1", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, DatabaseProvider: "sqlite", DatabaseMaxOpen: 10, DatabaseMaxIdle: 2, DatabaseConnectTimeout: 10 * time.Second, DatabaseConnMaxLifetime: 30 * time.Minute}
}

func Load(args []string, getenv func(string) string) (Config, error) {
	cfg := Defaults()
	databaseEnvironment := false
	// When the explicit --host/--port form is selected (CLI flags or
	// TRESTLE_HOST/TRESTLE_PORT environment), the legacy TRESTLE_LISTEN durable
	// value is overridden and must not fail validation: the CLI applies the
	// resolved host/port override after load.
	newListenerForm := getenv("TRESTLE_HOST") != "" || getenv("TRESTLE_PORT") != ""
	for _, a := range args {
		if a == "--host" || a == "--port" || strings.HasPrefix(a, "--host=") || strings.HasPrefix(a, "--port=") {
			newListenerForm = true
			break
		}
	}
	if value := getenv("TRESTLE_LISTEN"); value != "" && !newListenerForm {
		cfg.Listen = value
	}
	if value := getenv("TRESTLE_DATA_DIR"); value != "" {
		cfg.DataDir = value
	}
	if value := getenv("TRESTLE_SHUTDOWN_TIMEOUT"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = duration
	}
	if value := getenv("TRESTLE_LOG_LEVEL"); value != "" {
		cfg.LogLevel = value
	}
	if value := getenv("TRESTLE_STATIC_DIR"); value != "" {
		cfg.StaticDir = value
	}
	if value := getenv("TRESTLE_STORAGE_BACKEND"); value != "" {
		cfg.StorageBackend = value
	}
	cfg.S3Endpoint = getenv("TRESTLE_S3_ENDPOINT")
	if value := getenv("TRESTLE_S3_REGION"); value != "" {
		cfg.S3Region = value
	}
	cfg.S3Bucket = getenv("TRESTLE_S3_BUCKET")
	cfg.S3AccessKey = getenv("TRESTLE_S3_ACCESS_KEY")
	cfg.S3SecretKey = getenv("TRESTLE_S3_SECRET_KEY")
	cfg.AWSRegion = getenv("TRESTLE_AWS_REGION")
	cfg.AWSAccessKey = getenv("TRESTLE_AWS_ACCESS_KEY")
	cfg.AWSSecretKey = getenv("TRESTLE_AWS_SECRET_KEY")
	if v := getenv("TRESTLE_REPLICATION_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_REPLICATION_ENABLED: %w", err)
		}
		cfg.Replication.Enabled = b
	}
	cfg.Replication.NodeID = getenv("TRESTLE_REPLICATION_NODE_ID")
	if v := getenv("TRESTLE_REPLICATION_BOOTSTRAP"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_REPLICATION_BOOTSTRAP: %w", err)
		}
		cfg.Replication.Bootstrap = b
	}
	cfg.Replication.Listen = getenv("TRESTLE_REPLICATION_LISTEN")
	cfg.Replication.TLSCert = getenv("TRESTLE_REPLICATION_TLS_CERT")
	cfg.Replication.TLSKey = getenv("TRESTLE_REPLICATION_TLS_KEY")
	cfg.Replication.TLSCA = getenv("TRESTLE_REPLICATION_TLS_CA")
	if v := getenv("TRESTLE_REPLICATION_INSECURE_PLAINTEXT"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_REPLICATION_INSECURE_PLAINTEXT: %w", err)
		}
		cfg.Replication.InsecurePlaintext = b
	}
	if value := getenv("TRESTLE_TRUSTED_PROXIES"); value != "" {
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_TRUSTED_PROXIES: %w", err)
		}
		cfg.TrustedProxies = prefixes
	}
	if value := getenv("TRESTLE_READ_HEADER_TIMEOUT"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_READ_HEADER_TIMEOUT: %w", err)
		}
		cfg.ReadHeaderTimeout = duration
	}
	if value := getenv("TRESTLE_IDLE_TIMEOUT"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_IDLE_TIMEOUT: %w", err)
		}
		cfg.IdleTimeout = duration
	}
	if value := getenv("TRESTLE_READ_TIMEOUT"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_READ_TIMEOUT: %w", err)
		}
		cfg.ReadTimeout = duration
	}
	if value := getenv("TRESTLE_MAX_HEADER_BYTES"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_MAX_HEADER_BYTES: %w", err)
		}
		cfg.MaxHeaderBytes = n
	}
	if value := getenv("TRESTLE_DATABASE_PROVIDER"); value != "" {
		cfg.DatabaseProvider = value
		databaseEnvironment = true
	}
	if value := getenv("TRESTLE_DATABASE_URL"); value != "" {
		cfg.DatabaseURL = value
		databaseEnvironment = true
	}
	if value := getenv("TRESTLE_DATABASE_MAX_OPEN"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_DATABASE_MAX_OPEN: %w", err)
		}
		cfg.DatabaseMaxOpen = n
		databaseEnvironment = true
	}
	if value := getenv("TRESTLE_DATABASE_MAX_IDLE"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_DATABASE_MAX_IDLE: %w", err)
		}
		cfg.DatabaseMaxIdle = n
		databaseEnvironment = true
	}
	if value := getenv("TRESTLE_DATABASE_CONNECT_TIMEOUT"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_DATABASE_CONNECT_TIMEOUT: %w", err)
		}
		cfg.DatabaseConnectTimeout = d
		databaseEnvironment = true
	}
	if value := getenv("TRESTLE_DATABASE_CONN_MAX_LIFETIME"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("TRESTLE_DATABASE_CONN_MAX_LIFETIME: %w", err)
		}
		cfg.DatabaseConnMaxLifetime = d
		databaseEnvironment = true
	}

	set := flag.NewFlagSet("trestle", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address")
	// --host/--port are accepted here so the command line parses, but the config
	// layer does not apply them: the CLI resolves the listener and, when an
	// explicit host/port was selected, overrides the durable config listener in
	// memory after load. The legacy --listen flag and TRESTLE_LISTEN environment
	// variable keep their durable-config behavior.
	var cliHost, cliPort string
	set.StringVar(&cliHost, "host", "", "HTTP bind host")
	set.StringVar(&cliPort, "port", "", "HTTP bind port, 1-65535")
	set.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "data directory")
	set.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "graceful shutdown timeout")
	set.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug, info, warn, or error")
	set.StringVar(&cfg.StaticDir, "static-dir", cfg.StaticDir, "development static asset override")
	set.StringVar(&cfg.StorageBackend, "storage-backend", cfg.StorageBackend, "local or s3")
	var trustedProxies string
	if len(cfg.TrustedProxies) > 0 {
		trustedProxies = joinPrefixes(cfg.TrustedProxies)
	}
	set.StringVar(&trustedProxies, "trusted-proxies", trustedProxies, "comma-separated proxy CIDRs allowed to supply forwarded headers")
	set.DurationVar(&cfg.ReadHeaderTimeout, "read-header-timeout", cfg.ReadHeaderTimeout, "HTTP request header timeout")
	set.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "HTTP request read timeout including request bodies")
	set.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "HTTP keep-alive idle timeout")
	set.IntVar(&cfg.MaxHeaderBytes, "max-header-bytes", cfg.MaxHeaderBytes, "maximum HTTP request header bytes")
	set.StringVar(&cfg.DatabaseProvider, "database-provider", cfg.DatabaseProvider, "sqlite or postgres")
	set.StringVar(&cfg.DatabaseURL, "database-url", cfg.DatabaseURL, "PostgreSQL connection URL (secret)")
	set.IntVar(&cfg.DatabaseMaxOpen, "database-max-open", cfg.DatabaseMaxOpen, "maximum open database connections")
	set.IntVar(&cfg.DatabaseMaxIdle, "database-max-idle", cfg.DatabaseMaxIdle, "maximum idle database connections")
	set.DurationVar(&cfg.DatabaseConnectTimeout, "database-connect-timeout", cfg.DatabaseConnectTimeout, "database startup connection timeout")
	set.DurationVar(&cfg.DatabaseConnMaxLifetime, "database-conn-max-lifetime", cfg.DatabaseConnMaxLifetime, "maximum database connection lifetime")
	if err := set.Parse(args); err != nil {
		return Config{}, err
	}
	if set.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(set.Args(), " "))
	}
	databaseFlag := false
	set.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "database-") {
			databaseFlag = true
		}
	})
	cfg.DatabaseExplicit = databaseEnvironment || databaseFlag
	prefixes, err := parsePrefixes(trustedProxies)
	if err != nil {
		return Config{}, fmt.Errorf("trusted proxies: %w", err)
	}
	cfg.TrustedProxies = prefixes
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DataDir) == "" {
		return errors.New("data directory must not be empty")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if host == "" {
		return errors.New("listen address must specify a host explicitly")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("listen port must be between 1 and 65535")
	}
	if c.ShutdownTimeout <= 0 || c.ShutdownTimeout > 5*time.Minute {
		return errors.New("shutdown timeout must be greater than zero and no more than 5m")
	}
	if c.ReadHeaderTimeout <= 0 || c.ReadHeaderTimeout > time.Minute {
		return errors.New("read header timeout must be greater than zero and no more than 1m")
	}
	if c.ReadTimeout <= 0 || c.ReadTimeout > time.Hour {
		return errors.New("read timeout must be greater than zero and no more than 1h")
	}
	if c.IdleTimeout <= 0 || c.IdleTimeout > 10*time.Minute {
		return errors.New("idle timeout must be greater than zero and no more than 10m")
	}
	if c.MaxHeaderBytes < 8<<10 || c.MaxHeaderBytes > 4<<20 {
		return errors.New("max header bytes must be between 8192 and 4194304")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("log level must be debug, info, warn, or error")
	}
	if c.StorageBackend != "local" && c.StorageBackend != "s3" {
		return errors.New("storage backend must be local or s3")
	}
	if c.StorageBackend == "s3" {
		if c.S3Endpoint == "" || c.S3Bucket == "" || c.S3AccessKey == "" || c.S3SecretKey == "" {
			return errors.New("S3 endpoint, bucket, access key, and secret key are required")
		}
		if !strings.HasPrefix(c.S3Endpoint, "https://") && !strings.HasPrefix(c.S3Endpoint, "http://127.0.0.1") && !strings.HasPrefix(c.S3Endpoint, "http://localhost") {
			return errors.New("S3 endpoint must use HTTPS except on loopback")
		}
	}
	if c.DatabaseProvider != "sqlite" && c.DatabaseProvider != "postgres" {
		return errors.New("database provider must be sqlite or postgres")
	}
	if c.DatabaseMaxOpen < 1 || c.DatabaseMaxOpen > 500 || c.DatabaseMaxIdle < 0 || c.DatabaseMaxIdle > c.DatabaseMaxOpen {
		return errors.New("database pool bounds are invalid")
	}
	if c.DatabaseConnectTimeout <= 0 || c.DatabaseConnectTimeout > time.Minute {
		return errors.New("database connect timeout must be greater than zero and no more than 1m")
	}
	if c.DatabaseConnectTimeout%time.Second != 0 {
		return errors.New("database connect timeout must be a whole number of seconds")
	}
	if c.DatabaseConnMaxLifetime < 0 || c.DatabaseConnMaxLifetime > 24*time.Hour {
		return errors.New("database connection lifetime must be between 0 and 24h")
	}
	if c.DatabaseProvider == "sqlite" {
		if c.DatabaseURL != "" {
			return errors.New("database URL is only valid for postgres")
		}
	} else if err := validatePostgresURL(c.DatabaseURL); err != nil {
		return err
	}
	return nil
}

func FromOS(args []string) (Config, error) {
	cfg, err := Load(args, os.Getenv)
	if err != nil || cfg.DatabaseExplicit {
		return cfg, err
	}
	stored, found, err := ReadDatabaseBootstrap(cfg.DataDir)
	if err != nil {
		return Config{}, err
	}
	if found {
		cfg.DatabaseProvider = stored.Provider
		cfg.DatabaseURL = stored.URL
		cfg.DatabaseMaxOpen = stored.MaxOpen
		cfg.DatabaseMaxIdle = stored.MaxIdle
		cfg.DatabaseConnectTimeout = stored.ConnectTimeout
		cfg.DatabaseConnMaxLifetime = stored.ConnMaxLifetime
		cfg.DatabaseConfigured = true
	}
	return cfg, cfg.Validate()
}

func validatePostgresURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		return errors.New("postgres database URL must be a valid postgres:// or postgresql:// URL")
	}
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if !loopback && strings.EqualFold(u.Query().Get("sslmode"), "disable") {
		return errors.New("remote postgres connections must use TLS")
	}
	return nil
}

func RedactDatabaseURL(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return "[redacted database URL]"
	}
	if u.User != nil {
		u.User = url.UserPassword("[redacted]", "[redacted]")
	}
	return u.Redacted()
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, raw := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", strings.TrimSpace(raw))
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func joinPrefixes(values []netip.Prefix) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = value.String()
	}
	return strings.Join(parts, ",")
}
