package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/apidocs"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/backup"
	"github.com/trestle-cv/trestle/internal/buildinfo"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/config"
	"github.com/trestle-cv/trestle/internal/databasesetup"
	"github.com/trestle-cv/trestle/internal/deployment"
	"github.com/trestle-cv/trestle/internal/events"
	filestore "github.com/trestle-cv/trestle/internal/files"
	functionapi "github.com/trestle-cv/trestle/internal/functions"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/launcher"
	"github.com/trestle-cv/trestle/internal/records"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/server"
	"github.com/trestle-cv/trestle/internal/service"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/web"
	"github.com/trestle-cv/trestle/internal/webhooks"
)

// defaultListen matches the config default recorded for new installations.
const defaultListen = "127.0.0.1:7333"

func main() {
	// Service-management commands must remain usable even when the application
	// configuration is unhealthy, so dispatch before any runtime config load.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runService(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") &&
		os.Args[1] != "restore" && os.Args[1] != "migrate" {
		fmt.Fprintln(os.Stderr, "trestle: unknown command", os.Args[1])
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "restore" {
		set := flag.NewFlagSet("restore", flag.ContinueOnError)
		archive := set.String("backup", "", "backup archive path")
		dataDir := set.String("data-dir", "", "new restore data directory (SQLite)")
		provider := set.String("provider", "sqlite", "restore destination provider: sqlite or postgres")
		databaseURL := set.String("database-url", "", "PostgreSQL destination URL")
		if err := set.Parse(os.Args[2:]); err != nil || *archive == "" {
			fmt.Fprintln(os.Stderr, "usage: trestle restore --backup ARCHIVE [--data-dir DIR] [--provider sqlite|postgres] [--database-url URL]\n  PostgreSQL destinations must already be initialized at the current schema and empty")
			os.Exit(2)
		}
		restoreProvider, err := store.ParseProvider(*provider)
		if err != nil || (restoreProvider == store.SQLite && *dataDir == "") || (restoreProvider == store.Postgres && *databaseURL == "") {
			fmt.Fprintln(os.Stderr, "usage: trestle restore --backup ARCHIVE [--data-dir DIR] [--provider sqlite|postgres] [--database-url URL]\n  PostgreSQL destinations must already be initialized at the current schema and empty")
			os.Exit(2)
		}
		if err := backup.Restore(context.Background(), *archive, *dataDir, backup.RestoreOptions{Provider: restoreProvider, URL: *databaseURL}); err != nil {
			fmt.Fprintln(os.Stderr, "restore failed:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "restore complete:", *dataDir)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		set := flag.NewFlagSet("migrate", flag.ContinueOnError)
		fromProvider := set.String("from-provider", "", "source provider: sqlite or postgres")
		fromDir := set.String("from-dir", "", "source data directory (sqlite)")
		fromURL := set.String("from-url", "", "source PostgreSQL URL")
		toProvider := set.String("to-provider", "", "target provider: sqlite or postgres")
		toDir := set.String("to-dir", "", "target data directory (sqlite)")
		toURL := set.String("to-url", "", "target PostgreSQL URL")
		dryRun := set.Bool("dry-run", false, "export and validate without writing to the target")
		confirm := set.Bool("confirm-migration", false, "explicit confirmation for a real (non-dry-run) migration")
		if err := set.Parse(os.Args[2:]); err != nil {
			printMigrateUsage()
			os.Exit(2)
		}
		sourceProvider, err := store.ParseProvider(*fromProvider)
		if err != nil || *toProvider == "" {
			printMigrateUsage()
			os.Exit(2)
		}
		targetProvider, err := store.ParseProvider(*toProvider)
		if err != nil {
			printMigrateUsage()
			os.Exit(2)
		}
		report, err := backup.Migrate(context.Background(), backup.MigrateOptions{
			SourceProvider: sourceProvider, SourceDir: *fromDir, SourceURL: *fromURL,
			TargetProvider: targetProvider, TargetDir: *toDir, TargetURL: *toURL,
			DryRun: *dryRun, Confirm: *confirm,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "migration failed:", err)
			os.Exit(1)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			os.Exit(1)
		}
		return
	}

	// Resolve the requested listener (CLI --host/--port/--listen, then
	// TRESTLE_HOST/TRESTLE_PORT/TRESTLE_LISTEN, then defaults) before loading the
	// durable config, so explicit host/port selection can genuinely override the
	// durable config listener in memory below.
	listenerHost, listenerPort, listenerListen, hostSet, portSet, listenSet := listenerFlagsFromArgs(os.Args[1:])
	resolvedListen, listenerErr := resolveListener(listenerHost, listenerPort, listenerListen, hostSet, portSet, listenSet)
	if listenerErr != nil {
		slog.Error("invalid listener configuration", "error", listenerErr)
		os.Exit(2)
	}
	cfg, err := config.FromOS(os.Args[1:])
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	// An explicitly selected --host/--port (CLI or TRESTLE_HOST/TRESTLE_PORT)
	// overrides the durable config listener in memory, so the advertised override
	// controls the runtime listener. A bare invocation or a legacy --listen
	// selection keeps the durable config listener.
	if listenerOverrideSelected(hostSet, portSet) {
		cfg.Listen = resolvedListen
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	databaseContext, cancelDatabase := context.WithTimeout(context.Background(), cfg.DatabaseConnectTimeout)
	database, err := store.OpenWith(databaseContext, store.Options{DataDir: cfg.DataDir, Provider: store.Provider(cfg.DatabaseProvider), URL: cfg.DatabaseURL, MaxOpen: cfg.DatabaseMaxOpen, MaxIdle: cfg.DatabaseMaxIdle, ConnMaxLifetime: cfg.DatabaseConnMaxLifetime, ConnectTimeout: cfg.DatabaseConnectTimeout})
	cancelDatabase()
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	logger.Info("database ready", "provider", database.Provider(), "schema_version", store.CurrentVersion)
	dashboard, err := web.New(cfg.StaticDir)
	if err != nil {
		logger.Error("dashboard initialization failed", "error", err)
		os.Exit(1)
	}
	if cfg.StaticDir != "" {
		logger.Warn("using development static override", "directory", cfg.StaticDir)
	}
	admin := adminauth.New(database.DB(), string(database.Provider()))
	admin.SetSetupGuard(func(context.Context) error {
		stored, found, err := config.ReadDatabaseBootstrap(cfg.DataDir)
		if err != nil {
			return err
		}
		if found && stored.Provider != string(database.Provider()) {
			return errors.New("configured database is pending restart")
		}
		return nil
	})
	collectionAdmin := collections.New(database.DB(), admin)
	credentials := identities.New(database.DB(), admin)
	recordAPI := records.New(database.DB(), admin, credentials)
	applicationAuth := appauth.New(database.DB(), admin)
	accessRules := rules.New(database.DB(), admin)
	recordAPI.ConfigureAccess(applicationAuth, accessRules)
	eventAPI := events.New(database.DB(), admin, credentials)
	recordAPI.ConfigureEvents(eventAPI)
	auditAPI := audit.New(database.DB(), admin, string(database.Provider()))
	applicationAuth.SetAudit(auditAPI)
	jobAPI := jobs.New(database.DB(), admin)
	webhookAPI, err := webhooks.New(database.DB(), admin, jobAPI, cfg.DataDir)
	if err != nil {
		logger.Error("webhook initialization failed", "error", err)
		os.Exit(1)
	}
	eventAPI.ConfigureDispatcher(webhookAPI)
	functionAPI := functionapi.New(database.DB(), admin, jobAPI, functionapi.Options{Region: cfg.AWSRegion, AccessKey: cfg.AWSAccessKey, SecretKey: cfg.AWSSecretKey})
	apiDocs := apidocs.New(database.DB(), admin)
	backupAPI, err := backup.New(database.DB(), admin, cfg.DataDir, cfg.StorageBackend)
	if err != nil {
		logger.Error("backup initialization failed", "error", err)
		os.Exit(1)
	}
	deploymentAPI := deployment.New(admin, deployment.Options{Listen: cfg.Listen, StorageBackend: cfg.StorageBackend, TrustedProxies: cfg.TrustedProxies, ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes})
	eventAPI.ConfigureDispatcher(functionAPI)
	recordAPI.ConfigureAudit(auditAPI)
	fileAPI, err := filestore.New(database.DB(), admin, credentials, cfg.DataDir, filestore.Options{Backend: cfg.StorageBackend, S3Endpoint: cfg.S3Endpoint, S3Region: cfg.S3Region, S3Bucket: cfg.S3Bucket, S3AccessKey: cfg.S3AccessKey, S3SecretKey: cfg.S3SecretKey})
	if err != nil {
		logger.Error("file storage initialization failed", "error", err)
		os.Exit(1)
	}
	if pending, err := fileAPI.ResumePendingDeletions(context.Background()); err != nil {
		logger.Error("file deletion recovery failed", "error", err)
	} else if pending > 0 {
		logger.Info("resumed pending file deletions", "count", pending)
	}
	fileAPI.SetLogger(logger)
	apiRoutes := http.NewServeMux()
	apiRoutes.Handle("/api/v1/auth/", applicationAuth)
	apiRoutes.Handle("/api/v1/collections/", recordAPI)
	apiRoutes.Handle("/api/v1/files", fileAPI)
	apiRoutes.Handle("/api/v1/files/", fileAPI)
	apiRoutes.Handle("/api/v1/realtime", eventAPI)
	apiRoutes.Handle("/api/v1/openapi.json", apiDocs)
	apiRoutes.Handle("/api/v1/capabilities", apiDocs)
	adminRoutes := http.NewServeMux()
	databaseSetup := databasesetup.New(admin, databasesetup.Options{DataDir: cfg.DataDir, Current: database.Provider(), Explicit: cfg.DatabaseExplicit || cfg.DatabaseConfigured, MaxOpen: cfg.DatabaseMaxOpen, MaxIdle: cfg.DatabaseMaxIdle, ConnectTimeout: cfg.DatabaseConnectTimeout, ConnMaxLifetime: cfg.DatabaseConnMaxLifetime})
	adminRoutes.Handle("/admin/v1/database/setup", databaseSetup)
	adminRoutes.Handle("/admin/v1/collections", collectionAdmin)
	adminRoutes.Handle("/admin/v1/collections/", collectionAdmin)
	adminRoutes.Handle("/admin/v1/data/", recordAPI)
	adminRoutes.Handle("/admin/v1/app-users", applicationAuth)
	adminRoutes.Handle("/admin/v1/app-users/", applicationAuth)
	adminRoutes.Handle("/admin/v1/app-registration", applicationAuth)
	adminRoutes.Handle("/admin/v1/app-registration/", applicationAuth)
	adminRoutes.Handle("/admin/v1/credentials", credentials)
	adminRoutes.Handle("/admin/v1/credentials/", credentials)
	adminRoutes.Handle("/admin/v1/collection-rules/", accessRules)
	adminRoutes.Handle("/admin/v1/files", fileAPI)
	adminRoutes.Handle("/admin/v1/files/", fileAPI)
	adminRoutes.Handle("/admin/v1/storage/status", fileAPI)
	adminRoutes.Handle("/admin/v1/events", eventAPI)
	adminRoutes.Handle("/admin/v1/audit", auditAPI)
	adminRoutes.Handle("/admin/v1/operations", auditAPI)
	adminRoutes.Handle("/admin/v1/jobs", jobAPI)
	adminRoutes.Handle("/admin/v1/jobs/", jobAPI)
	adminRoutes.Handle("/admin/v1/webhooks", webhookAPI)
	adminRoutes.Handle("/admin/v1/webhooks/", webhookAPI)
	adminRoutes.Handle("/admin/v1/functions", functionAPI)
	adminRoutes.Handle("/admin/v1/functions/", functionAPI)
	adminRoutes.Handle("/admin/v1/api/schema", apiDocs)
	adminRoutes.Handle("/admin/v1/backups", backupAPI)
	adminRoutes.Handle("/admin/v1/backups/", backupAPI)
	adminRoutes.Handle("/admin/v1/restores/preflight", backupAPI)
	adminRoutes.Handle("/admin/v1/export", backupAPI)
	adminRoutes.Handle("/admin/v1/imports/dry-run", backupAPI)
	adminRoutes.Handle("/admin/v1/deployment", deploymentAPI)
	adminRoutes.Handle("/admin/v1/support-bundle", deploymentAPI)
	adminRoutes.Handle("/", admin)
	launcherUI := launcher.New(database.DB(), admin, dashboard)
	launcherRoutes := http.NewServeMux()
	launcherRoutes.HandleFunc("/api/launcher/instances", launcherUI.Instances)
	launcherRoutes.HandleFunc("/api/launcher/config", launcherUI.Config)
	app := server.NewWithOptions(logger, dashboard, apiRoutes, adminRoutes, server.Options{TrustedProxies: cfg.TrustedProxies, Root: http.HandlerFunc(launcherUI.Root), Manage: admin.ManagePage(dashboard), LauncherAPI: launcherRoutes})
	app.SetDatabaseCheck(database.Ping)
	httpServer := &http.Server{Addr: cfg.Listen, Handler: app.Handler(), ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobAPI.Start(ctx)
	go fileAPI.RunDeletionRecovery(ctx, 5*time.Minute)
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "listen", cfg.Listen, "data_dir", cfg.DataDir, "trusted_proxy_count", len(cfg.TrustedProxies), "read_header_timeout", cfg.ReadHeaderTimeout, "read_timeout", cfg.ReadTimeout, "idle_timeout", cfg.IdleTimeout, "max_header_bytes", cfg.MaxHeaderBytes)
		app.SetReady(true)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case err = <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			// Retain the OS bind error and identify the requested listener so a
			// failed bind is attributable to the exact host/port selection.
			logger.Error("server failed", "error", err, "listener", cfg.Listen)
			os.Exit(1)
		}
		return
	case <-ctx.Done():
	}
	app.SetReady(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func printMigrateUsage() {
	fmt.Fprintln(os.Stderr, "usage: trestle migrate --from-provider sqlite|postgres --from-dir DIR|--from-url URL --to-provider sqlite|postgres --to-dir DIR|--to-url URL [--dry-run] [--confirm-migration]")
}

// serviceFlagTakesValue reports whether a `trestle service` flag consumes the
// following argv token as its value. The install family (--data-dir, the
// legacy --data alias, --listen, --host, --port, --env-file) does; --follow
// and the lifecycle commands do not.
func serviceFlagTakesValue(name string) bool {
	switch name {
	case "--data-dir", "--data", "--listen", "--host", "--port", "--env-file":
		return true
	}
	return false
}

// runService dispatches `trestle service <command>` operating the Trestle
// systemd **system** unit. Exit codes: 0 success, 1 operational failure, 2
// usage error (canonical Web Fleet convention).
func runService(args []string) int {
	cmd := "status"
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a != "" && !strings.HasPrefix(a, "-") {
			if cmd == "status" && len(positional) == 0 {
				cmd = a
				continue
			}
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		// A value-taking flag consumes the next token as its value so the value
		// is not misclassified as a positional argument.
		if serviceFlagTakesValue(a) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			flags = append(flags, args[i])
		}
	}
	usage := func(msg string) int {
		fmt.Fprintf(os.Stderr, "trestle service %s: %s\n", cmd, msg)
		return 2
	}
	if len(flags) > 0 {
		switch cmd {
		case "install":
			for i := 0; i < len(flags); i++ {
				switch flags[i] {
				case "--data-dir", "--data":
					if i+1 < len(flags) {
						i++
					} else {
						return usage(flags[i] + " requires a path")
					}
				case "--listen":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--listen requires an address")
					}
				case "--host":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--host requires an address")
					}
				case "--port":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--port requires a value")
					}
				case "--env-file":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--env-file requires a path")
					}
				default:
					return usage("unknown flag " + flags[i])
				}
			}
		case "logs":
			if len(flags) > 1 || flags[0] != "--follow" {
				return usage("logs accepts only --follow")
			}
		default:
			return usage("no flags are accepted for " + cmd)
		}
	}
	switch cmd {
	case "install":
		if len(positional) != 0 {
			return usage("install takes no positional arguments")
		}
		data := service.DefaultDataDir
		envfile := ""
		var hostVal, portVal, listenVal string
		var hostSet, portSet, listenSet bool
		for i := 0; i < len(flags); i++ {
			switch flags[i] {
			case "--data-dir", "--data":
				if i+1 < len(flags) {
					i++
					data = flags[i]
				}
			case "--listen":
				if i+1 < len(flags) {
					i++
					listenVal, listenSet = flags[i], true
				}
			case "--host":
				if i+1 < len(flags) {
					i++
					hostVal, hostSet = flags[i], true
				}
			case "--port":
				if i+1 < len(flags) {
					i++
					portVal, portSet = flags[i], true
				}
			case "--env-file":
				if i+1 < len(flags) {
					i++
					envfile = flags[i]
				}
			}
		}
		// Only `service install` resolves listener flags and environment: a
		// malformed TRESTLE_HOST/TRESTLE_PORT in the invoking shell must never
		// break start/stop/restart/status/logs/uninstall.
		addr, resolveErr := resolveListener(hostVal, portVal, listenVal, hostSet, portSet, listenSet)
		if resolveErr != nil {
			fmt.Fprintln(os.Stderr, "trestle service install:", resolveErr)
			return 2
		}
		legacy := listenSet
		if !legacy {
			if _, hasListen := os.LookupEnv("TRESTLE_LISTEN"); hasListen && !hostSet && !portSet {
				legacy = true
			}
		}
		if legacy {
			if err := service.Install(service.Executable(), data, addr, envfile); err != nil {
				fmt.Fprintln(os.Stderr, "trestle service install:", err)
				return 1
			}
		} else {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				fmt.Fprintln(os.Stderr, "trestle service install:", err)
				return 2
			}
			if err := service.InstallExplicit(service.Executable(), data, host, port, envfile); err != nil {
				fmt.Fprintln(os.Stderr, "trestle service install:", err)
				return 1
			}
		}
		fmt.Fprintln(os.Stdout, "trestle.service installed.")
		return 0
	case "uninstall":
		if len(positional) != 0 {
			return usage("uninstall takes no positional arguments")
		}
		if err := service.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service uninstall:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "trestle.service uninstalled. Trestle data was preserved.")
		return 0
	case "start", "stop", "restart", "enable", "disable":
		if len(positional) != 0 {
			return usage(cmd + " takes no positional arguments")
		}
		if err := lifecycleErr(cmd); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service "+cmd+":", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, serviceLifecycleSuccess(cmd))
		return 0
	case "status":
		if len(positional) != 0 {
			return usage("status takes no positional arguments")
		}
		if err := service.Status(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service status:", err)
			return 1
		}
		return 0
	case "logs":
		if len(positional) != 0 {
			return usage("logs takes no positional arguments")
		}
		follow := len(flags) > 0 && flags[0] == "--follow"
		if err := service.Logs(follow, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service logs:", err)
			return 1
		}
		return 0
	case "update":
		if len(positional) != 2 {
			return usage("usage: trestle service update ARTIFACT SHA256")
		}
		if err := service.Update(positional[0], positional[1]); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service update:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "trestle.service updated.")
		return 0
	case "rollback":
		if len(positional) != 0 {
			return usage("rollback takes no positional arguments")
		}
		if err := service.Rollback(); err != nil {
			fmt.Fprintln(os.Stderr, "trestle service rollback:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "trestle.service rolled back.")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "trestle: unknown service command %q\n\nUsage: trestle service <install|uninstall|start|stop|restart|status|enable|disable|logs|update|rollback> [flags]\n", cmd)
		return 2
	}
}

func serviceLifecycleSuccess(verb string) string {
	switch verb {
	case "start":
		return "trestle.service started."
	case "stop":
		return "trestle.service stopped."
	case "restart":
		return "trestle.service restarted."
	case "enable":
		return "trestle.service enabled."
	case "disable":
		return "trestle.service disabled."
	default:
		return "trestle.service updated."
	}
}

func lifecycleErr(verb string) error {
	switch verb {
	case "start":
		return service.Start()
	case "stop":
		return service.Stop()
	case "restart":
		return service.Restart()
	case "enable":
		return service.Enable()
	case "disable":
		return service.Disable()
	}
	return fmt.Errorf("unknown lifecycle verb")
}
