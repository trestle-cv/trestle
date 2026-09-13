package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/config"
	"github.com/trestle-cv/trestle/internal/store"
)

func runSetup(args []string) int {
	fs := flag.NewFlagSet("trestle setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	email := fs.String("email", "", "administrator email")
	emailFile := fs.String("email-file", "", "file containing administrator email")
	passwordFile := fs.String("password-file", "", "file containing password")
	policy := fs.String("registration-policy", "closed", "closed, approval, invite or open")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *passwordFile == "" {
		fmt.Fprintln(os.Stderr, "usage: trestle setup (--email ADDRESS|--email-file FILE) --password-file FILE [--registration-policy closed|approval|invite|open]")
		return 2
	}
	if *emailFile != "" {
		raw, err := os.ReadFile(*emailFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
		*email = strings.TrimSpace(string(raw))
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "trestle: --email or --email-file is required")
		return 2
	}
	password, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	cfg, err := config.FromOS(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	provider, err := store.ParseProvider(cfg.DatabaseProvider)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	db, err := store.OpenWith(context.Background(), store.Options{DataDir: cfg.DataDir, Provider: provider, URL: cfg.DatabaseURL, MaxOpen: cfg.DatabaseMaxOpen, MaxIdle: cfg.DatabaseMaxIdle, ConnectTimeout: cfg.DatabaseConnectTimeout, ConnMaxLifetime: cfg.DatabaseConnMaxLifetime})
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	defer db.Close()
	if err = adminauth.New(db.DB(), cfg.DatabaseProvider).SetupAdministrator(context.Background(), *email, strings.TrimRight(string(password), "\r\n"), *policy); err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	fmt.Println("Trestle administrator configured.")
	return 0
}

func runConfig(args []string) int {
	fs := flag.NewFlagSet("trestle config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || fs.Arg(0) != "show" {
		fmt.Fprintln(os.Stderr, "usage: trestle config show [--json]")
		return 2
	}
	cfg, err := config.FromOS(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	v := map[string]any{"project": "trestle", "dataDir": cfg.DataDir, "databaseProvider": cfg.DatabaseProvider, "listen": cfg.Listen}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(v)
	} else {
		fmt.Printf("Data directory: %s\nDatabase: %s\nListen: %s\n", cfg.DataDir, cfg.DatabaseProvider, cfg.Listen)
	}
	return 0
}

func runReset(args []string) int {
	fs := flag.NewFlagSet("trestle reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	auth := fs.Bool("auth", false, "reset authentication state")
	all := fs.Bool("all", false, "reset all Trestle state")
	confirm := fs.String("confirm", "", "non-interactive confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*auth == *all) {
		fmt.Fprintln(os.Stderr, "usage: trestle reset (--auth|--all) [--confirm 'TRESTLE AUTH|TRESTLE ALL']")
		return 2
	}
	cfg, err := config.FromOS(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trestle:", err)
		return 1
	}
	mode := "AUTH"
	if *all {
		mode = "ALL"
	}
	want := "TRESTLE " + mode
	if !confirmTrestle(want, *confirm) {
		fmt.Fprintln(os.Stderr, "trestle: confirmation did not match; nothing changed")
		return 1
	}
	if cfg.DatabaseProvider != "sqlite" {
		fmt.Fprintln(os.Stderr, "trestle: reset currently requires SQLite; use a database-native backup/reset workflow for PostgreSQL")
		return 1
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if *all {
		if _, err = os.Stat(cfg.DataDir); os.IsNotExist(err) {
			return 0
		}
		if err = os.Rename(cfg.DataDir, cfg.DataDir+".reset-"+stamp); err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
		if err = os.MkdirAll(cfg.DataDir, 0700); err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
	} else {
		db, openErr := store.Open(context.Background(), cfg.DataDir)
		if openErr != nil {
			fmt.Fprintln(os.Stderr, "trestle:", openErr)
			return 1
		}
		_ = db.Close()
		source := filepath.Join(cfg.DataDir, "trestle.db")
		if err = copyResetFile(source, filepath.Join(cfg.DataDir, "reset-auth-"+stamp+".db")); err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
		db, err = store.Open(context.Background(), cfg.DataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
		defer db.Close()
		tx, beginErr := db.DB().Begin()
		if beginErr != nil {
			fmt.Fprintln(os.Stderr, "trestle:", beginErr)
			return 1
		}
		defer tx.Rollback()
		for _, q := range []string{"DELETE FROM _trestle_app_access", "DELETE FROM _trestle_app_sessions", "DELETE FROM _trestle_app_invitations", "DELETE FROM _trestle_app_access_requests", "DELETE FROM _trestle_app_users", "DELETE FROM _trestle_credentials", "DELETE FROM _trestle_admin_sessions", "DELETE FROM _trestle_admin_roles", "DELETE FROM _trestle_admins"} {
			if _, err = tx.Exec(q); err != nil {
				fmt.Fprintln(os.Stderr, "trestle:", err)
				return 1
			}
		}
		if err = tx.Commit(); err != nil {
			fmt.Fprintln(os.Stderr, "trestle:", err)
			return 1
		}
	}
	fmt.Printf("Trestle %s reset complete. A timestamped backup was retained.\n", strings.ToLower(mode))
	return 0
}

func confirmTrestle(want, supplied string) bool {
	if supplied != "" {
		return supplied == want
	}
	fmt.Fprintf(os.Stderr, "Type %q to continue: ", want)
	got, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(got) == want
}
func copyResetFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
