package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/trestle-cv/trestle/internal/buildinfo"
	clusterapi "github.com/trestle-cv/trestle/internal/cluster"
	"github.com/trestle-cv/trestle/internal/config"
	"github.com/trestle-cv/trestle/internal/store"
)

func openClusterService() (*store.Store, *clusterapi.Service, *clusterapi.Transport, error) {
	cfg, err := config.FromOS(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DatabaseConnectTimeout)
	defer cancel()
	st, err := store.OpenWith(ctx, store.Options{DataDir: cfg.DataDir, Provider: store.Provider(cfg.DatabaseProvider), URL: cfg.DatabaseURL, MaxOpen: cfg.DatabaseMaxOpen, MaxIdle: cfg.DatabaseMaxIdle, ConnMaxLifetime: cfg.DatabaseConnMaxLifetime, ConnectTimeout: cfg.DatabaseConnectTimeout})
	if err != nil {
		return nil, nil, nil, err
	}
	svc := clusterapi.New(st.DB())
	svc.SetInsecurePlaintext(cfg.Replication.InsecurePlaintext)
	transport := clusterapi.NewTransport(st.DB(), svc, nil)
	transport.SetInsecurePlaintext(cfg.Replication.InsecurePlaintext)
	return st, svc, transport, nil
}

func runCluster(args []string) int {
	if len(args) == 0 {
		printClusterUsage()
		return 2
	}
	st, svc, transport, err := openClusterService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cluster:", err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("cluster init", flag.ContinueOnError)
		name := fs.String("name", "", "node display name")
		endpoint := fs.String("endpoint", "", "public HTTPS endpoint")
		jsonOut := fs.Bool("json", false, "JSON output")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		v, e := svc.UpdateIdentity(ctx, *name, *endpoint, buildinfo.Current().Version)
		return clusterPrint(v, e, *jsonOut)
	case "invite":
		fs := flag.NewFlagSet("cluster invite", flag.ContinueOnError)
		secretFile := fs.String("secret-file", "", "write the one-time invitation token to this file")
		jsonOut := fs.Bool("json", false, "JSON output")
		if fs.Parse(args[1:]) != nil || strings.TrimSpace(*secretFile) == "" {
			fmt.Fprintln(os.Stderr, "usage: trestle cluster invite --secret-file FILE [--json]")
			return 2
		}
		inv, token, e := svc.Invite(ctx)
		if e == nil {
			e = writeSecret(*secretFile, token)
		}
		return clusterPrint(inv, e, *jsonOut)
	case "join":
		fs := flag.NewFlagSet("cluster join", flag.ContinueOnError)
		remote := fs.String("url", "", "remote Trestle HTTPS URL (HTTP only when TRESTLE_REPLICATION_INSECURE_PLAINTEXT is enabled for a trusted private network; disables TLS confidentiality)")
		tokenFile := fs.String("token-file", "", "invitation token file")
		jsonOut := fs.Bool("json", false, "JSON output")
		if fs.Parse(args[1:]) != nil || *remote == "" || *tokenFile == "" {
			fmt.Fprintln(os.Stderr, "usage: trestle cluster join --url URL --token-file FILE [--json]")
			return 2
		}
		token, e := readSecret(*tokenFile)
		if e != nil {
			return clusterPrint(nil, e, *jsonOut)
		}
		v, e := svc.BeginOutbound(ctx, *remote, token, nil)
		return clusterPrint(v, e, *jsonOut)
	case "approve", "reject":
		fs := flag.NewFlagSet("cluster "+args[0], flag.ContinueOnError)
		id := fs.String("id", "", "join request id")
		if fs.Parse(args[1:]) != nil || *id == "" {
			return 2
		}
		e := svc.DecideJoin(ctx, *id, args[0] == "approve")
		return clusterPrint(map[string]bool{"ok": e == nil}, e, true)
	case "joins":
		v, e := svc.PendingJoins(ctx)
		return clusterPrint(v, e, true)
	case "collect":
		fs := flag.NewFlagSet("cluster collect", flag.ContinueOnError)
		id := fs.String("id", "", "outbound join id")
		if fs.Parse(args[1:]) != nil || *id == "" {
			return 2
		}
		v, e := svc.CollectOutbound(ctx, *id, nil)
		return clusterPrint(v, e, true)
	case "members":
		v, e := svc.Members(ctx)
		return clusterPrint(v, e, true)
	case "status":
		fs := flag.NewFlagSet("cluster status", flag.ContinueOnError)
		target := fs.String("target", "all", "local|all|members|node:<id>")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		local, e := svc.LocalSummary(ctx)
		if e != nil {
			return clusterPrint(nil, e, true)
		}
		ms, e := svc.Members(ctx)
		if e != nil {
			return clusterPrint(nil, e, true)
		}
		remote := clusterapi.RemoteReader{Transport: transport}
		v, e := clusterapi.Aggregate(ctx, local.NodeID, local, ms, *target, remote.Summary)
		return clusterPrint(v, e, true)
	case "rotate", "revoke", "remove":
		fs := flag.NewFlagSet("cluster "+args[0], flag.ContinueOnError)
		id := fs.String("id", "", "member node id")
		secretFile := fs.String("secret-file", "", "write rotated credential to this file")
		if fs.Parse(args[1:]) != nil || *id == "" {
			return 2
		}
		if args[0] == "rotate" {
			secret, e := svc.Rotate(ctx, *id)
			if e == nil {
				if *secretFile == "" {
					e = errors.New("--secret-file is required for rotate")
				} else {
					e = writeSecret(*secretFile, secret)
				}
			}
			return clusterPrint(map[string]bool{"rotated": e == nil}, e, true)
		}
		if args[0] == "revoke" {
			err = svc.Revoke(ctx, *id)
		} else {
			err = svc.Remove(ctx, *id)
		}
		return clusterPrint(map[string]bool{"ok": err == nil}, err, true)
	default:
		printClusterUsage()
		return 2
	}
}

func clusterPrint(v any, err error, jsonOut bool) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, "cluster:", err)
		return 1
	}
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(v)
		return 0
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(os.Stdout, string(b))
	return 0
}
func writeSecret(path, value string) error { return os.WriteFile(path, []byte(value+"\n"), 0o600) }
func readSecret(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("empty secret file")
	}
	return v, nil
}
func printClusterUsage() {
	fmt.Fprintln(os.Stderr, "usage: trestle cluster init|invite|join|approve|reject|joins|collect|members|status|rotate|revoke|remove")
}
