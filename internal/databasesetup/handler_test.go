package databasesetup

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/config"
	"github.com/trestle-cv/trestle/internal/store"
)

func TestFirstRunDatabaseSelectionPersistsSQLite(t *testing.T) {
	dir := t.TempDir()
	database, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := New(adminauth.New(database.DB()), Options{DataDir: dir, Current: store.SQLite, MaxOpen: 10, MaxIdle: 2, ConnectTimeout: time.Second, ConnMaxLifetime: time.Hour})
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/database/setup", strings.NewReader(`{"provider":"sqlite","url":""}`))
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	stored, found, err := config.ReadDatabaseBootstrap(dir)
	if err != nil || !found || stored.Provider != "sqlite" {
		t.Fatalf("stored=%#v found=%v err=%v", stored, found, err)
	}
}

func TestExplicitAndCompletedSetupRefuseMutation(t *testing.T) {
	dir := t.TempDir()
	database, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	admin := adminauth.New(database.DB())
	h := New(admin, Options{DataDir: dir, Current: store.SQLite, Explicit: true, ConnectTimeout: time.Second})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/v1/database/setup", strings.NewReader(`{"provider":"sqlite"}`)))
	if w.Code != 409 {
		t.Fatalf("explicit status=%d", w.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"mudblood","applicationRegistrationPolicy":"closed"}`))
	request.Host = "example.test"
	response := httptest.NewRecorder()
	admin.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/v1/database/setup", nil))
	if w.Code != 409 {
		var body any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		t.Fatalf("completed status=%d body=%v", w.Code, body)
	}
	var completed struct {
		Error struct {
			Code, Message string
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.Error.Code != "setup_complete" || completed.Error.Message == "" {
		t.Fatalf("completed envelope=%#v", completed)
	}
}

func TestDatabaseSetupErrorsUseStandardEnvelope(t *testing.T) {
	dir := t.TempDir()
	database, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := New(adminauth.New(database.DB()), Options{DataDir: dir, Current: store.SQLite, MaxOpen: 10, MaxIdle: 2, ConnectTimeout: time.Second})
	submit := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/v1/database/setup", strings.NewReader(body))
		r.Host = "example.test"
		r.Header.Set("Origin", "http://example.test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var envelope struct {
		Error struct {
			Code, Message string
		} `json:"error"`
	}
	invalid := submit(`{"provider":"mysql"}`)
	if invalid.Code != 422 {
		t.Fatalf("invalid provider status=%d", invalid.Code)
	}
	if err := json.Unmarshal(invalid.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(envelope.Error.Message, "sqlite or postgres") {
		t.Fatalf("invalid provider message=%q", envelope.Error.Message)
	}
	tls := submit(`{"provider":"postgres","url":"postgres://u:p@db.example/x?sslmode=disable"}`)
	if tls.Code != 422 {
		t.Fatalf("remote tls status=%d body=%s", tls.Code, tls.Body.String())
	}
	if err := json.Unmarshal(tls.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(envelope.Error.Message, "TLS") {
		t.Fatalf("remote tls message=%q", envelope.Error.Message)
	}
	if strings.Contains(tls.Body.String(), "u:p") {
		t.Fatal("credential leaked in response")
	}
	unreachable := submit(`{"provider":"postgres","url":"postgres://u:p@127.0.0.1:5999/nope?sslmode=disable"}`)
	if unreachable.Code != 422 {
		t.Fatalf("unreachable status=%d body=%s", unreachable.Code, unreachable.Body.String())
	}
	if err := json.Unmarshal(unreachable.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(envelope.Error.Message, "postgres connection failed") {
		t.Fatalf("unreachable message=%q", envelope.Error.Message)
	}
	if strings.Contains(unreachable.Body.String(), "u:p") {
		t.Fatal("credential leaked in response")
	}
	origin := httptest.NewRequest(http.MethodPost, "/admin/v1/database/setup", strings.NewReader(`{"provider":"sqlite"}`))
	origin.Host = "example.test"
	origin.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, origin)
	if w.Code != 403 {
		t.Fatalf("origin status=%d body=%s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Message == "" {
		t.Fatal("origin rejection has no useful message")
	}
}

func TestDatabaseSetupConnectionTimeoutReturnsUsefulError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	released := make(chan struct{})
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		<-released
		conn.Close()
		close(done)
	}()
	dir := t.TempDir()
	database, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := New(adminauth.New(database.DB()), Options{DataDir: dir, Current: store.SQLite, MaxOpen: 10, MaxIdle: 2, ConnectTimeout: 2 * time.Second})
	url := "postgres://u:p@" + ln.Addr().String() + "/nope?sslmode=disable"
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/database/setup", strings.NewReader(`{"provider":"postgres","url":"`+url+`"}`))
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(w, r)
	elapsed := time.Since(start)
	if w.Code != 422 {
		t.Fatalf("timeout status=%d body=%s", w.Code, w.Body.String())
	}
	if elapsed < 1700*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("setup probe returned in %s; expected ~2s bound", elapsed)
	}
	var envelope struct {
		Error struct {
			Code, Message string
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(envelope.Error.Message, "postgres connection failed") {
		t.Fatalf("timeout message=%q", envelope.Error.Message)
	}
	if strings.Contains(w.Body.String(), "u:p") {
		t.Fatal("credential leaked in response")
	}
	close(released)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stall goroutine did not exit")
	}
}
