package records

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/storetest"
)

type securityFixture struct {
	records     *Handler
	users       *appauth.Handler
	credentials *identities.Handler
	admin       session
}

func setupSecurityFixture(t *testing.T, provider string) securityFixture {
	t.Helper()
	database := storetest.Open(t, provider)
	admin := adminauth.New(database.DB(), string(database.Provider()))
	setup := invoke(t, admin, session{}, http.MethodPost, "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.test", "password": "mudblood", "applicationRegistrationPolicy": "closed"}, nil)
	var setupBody struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(setup.Body.Bytes(), &setupBody)
	adminSession := session{cookie: setup.Result().Cookies()[0], csrf: setupBody.CSRF}
	schema := collections.New(database.DB(), admin)
	created := invoke(t, schema, adminSession, http.MethodPost, "/admin/v1/collections", map[string]any{"name": "secured", "fields": []map[string]any{{"name": "title", "type": "text", "required": true}, {"name": "owner", "type": "text", "required": true}}}, nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("collection: %d %s", created.Code, created.Body.String())
	}
	users := appauth.New(database.DB(), admin)
	users.SetAudit(audit.New(database.DB(), admin, string(database.Provider())))
	if _, err := database.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	credentials := identities.New(database.DB(), admin)
	ruleHandler := rules.New(database.DB(), admin)
	recordHandler := New(database.DB(), admin, credentials)
	recordHandler.ConfigureAccess(users, ruleHandler)
	return securityFixture{recordHandler, users, credentials, adminSession}
}

func appUser(t *testing.T, users *appauth.Handler, email string) (string, string, string) {
	t.Helper()
	register := invoke(t, users, session{}, http.MethodPost, "/api/v1/auth/register", map[string]any{"email": email, "password": "1234567"}, nil)
	if register.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", register.Code, register.Body.String())
	}
	login := invoke(t, users, session{}, http.MethodPost, "/api/v1/auth/login", map[string]any{"email": email, "password": "1234567"}, nil)
	var tokens struct{ AccessToken, RefreshToken string }
	json.Unmarshal(login.Body.Bytes(), &tokens)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	id, ok := users.Authenticate(r)
	if !ok {
		t.Fatal("new access token did not authenticate")
	}
	return id, tokens.AccessToken, tokens.RefreshToken
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestAuthorizationAbuseMatrix(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f := setupSecurityFixture(t, provider)
			runAuthorizationAbuseMatrix(t, f)
		})
	}
}

func runAuthorizationAbuseMatrix(t *testing.T, f securityFixture) {
	userA, accessA, refreshA := appUser(t, f.users, "a@example.test")
	userB, accessB, _ := appUser(t, f.users, "b@example.test")
	for _, operation := range []string{"list", "view", "update", "delete"} {
		if _, err := f.records.db.Exec(`INSERT INTO _trestle_collection_rules(collection_id,operation,expression,updated_at) VALUES((SELECT id FROM _trestle_collections WHERE name='secured'),?,?,?)`, operation, "actor.id == record.owner", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.records.db.Exec(`INSERT INTO _trestle_collection_rules(collection_id,operation,expression,updated_at) VALUES((SELECT id FROM _trestle_collections WHERE name='secured'),'create','actor.id == input.owner',?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	create := func(owner, title string) Record {
		w := invoke(t, f.records, f.admin, http.MethodPost, "/api/v1/collections/secured/records", map[string]any{"values": map[string]any{"title": title, "owner": owner}}, nil)
		var record Record
		json.Unmarshal(w.Body.Bytes(), &record)
		return record
	}
	recordA := create(userA, "visible-a")
	recordB := create(userB, "hidden-b")

	listA := invoke(t, f.records, session{}, http.MethodGet, "/api/v1/collections/secured/records", nil, bearer(accessA))
	if listA.Code != 200 || !containsBody(listA, recordA.ID) || containsBody(listA, recordB.ID) {
		t.Fatalf("row-filtered list leaked: %d %s", listA.Code, listA.Body.String())
	}
	viewOther := invoke(t, f.records, session{}, http.MethodGet, "/api/v1/collections/secured/records/"+recordB.ID, nil, bearer(accessA))
	if viewOther.Code != 404 {
		t.Fatalf("cross-owner view leaked status: %d %s", viewOther.Code, viewOther.Body.String())
	}
	updateOther := invoke(t, f.records, session{}, http.MethodPatch, "/api/v1/collections/secured/records/"+recordB.ID, map[string]any{"values": map[string]any{"title": "stolen"}}, map[string]string{"Authorization": "Bearer " + accessA, "If-Match": `"1"`})
	if updateOther.Code != 404 {
		t.Fatalf("cross-owner update: %d %s", updateOther.Code, updateOther.Body.String())
	}
	createOther := invoke(t, f.records, session{}, http.MethodPost, "/api/v1/collections/secured/records", map[string]any{"values": map[string]any{"title": "forged", "owner": userB}}, bearer(accessA))
	if createOther.Code != 403 {
		t.Fatalf("forged owner create: %d %s", createOther.Code, createOther.Body.String())
	}
	refreshAsAccess := invoke(t, f.records, session{}, http.MethodGet, "/api/v1/collections/secured/records", nil, bearer(refreshA))
	if refreshAsAccess.Code != 401 {
		t.Fatalf("refresh token confused for access: %d", refreshAsAccess.Code)
	}
	viewOwn := invoke(t, f.records, session{}, http.MethodGet, "/api/v1/collections/secured/records/"+recordB.ID, nil, bearer(accessB))
	if viewOwn.Code != 200 {
		t.Fatalf("owner denied: %d %s", viewOwn.Code, viewOwn.Body.String())
	}
	readCredential := invoke(t, f.credentials, f.admin, http.MethodPost, "/admin/v1/credentials", map[string]any{"kind": "service", "name": "reader", "scopes": []string{"records:read"}}, nil)
	var reader struct{ ID, Secret string }
	json.Unmarshal(readCredential.Body.Bytes(), &reader)
	serviceRecord := create(reader.ID, "service-owned")
	serviceList := invoke(t, f.records, session{}, http.MethodGet, "/api/v1/collections/secured/records", nil, bearer(reader.Secret))
	if serviceList.Code != 200 || !containsBody(serviceList, serviceRecord.ID) || containsBody(serviceList, recordA.ID) {
		t.Fatalf("service row scope: %d %s", serviceList.Code, serviceList.Body.String())
	}
	serviceWrite := invoke(t, f.records, session{}, http.MethodPost, "/api/v1/collections/secured/records", map[string]any{"values": map[string]any{"title": "scope escalation", "owner": reader.ID}}, bearer(reader.Secret))
	if serviceWrite.Code != 403 {
		t.Fatalf("read scope wrote record: %d %s", serviceWrite.Code, serviceWrite.Body.String())
	}
	writeCredential := invoke(t, f.credentials, f.admin, http.MethodPost, "/admin/v1/credentials", map[string]any{"kind": "service", "name": "writer", "scopes": []string{"records:read", "records:write"}}, nil)
	var writer struct{ ID, Secret string }
	json.Unmarshal(writeCredential.Body.Bytes(), &writer)
	serviceWrite = invoke(t, f.records, session{}, http.MethodPost, "/api/v1/collections/secured/records", map[string]any{"values": map[string]any{"title": "authorized service", "owner": writer.ID}}, bearer(writer.Secret))
	if serviceWrite.Code != 201 {
		t.Fatalf("scoped bearer write denied: %d %s", serviceWrite.Code, serviceWrite.Body.String())
	}
}

func containsBody(response *httptest.ResponseRecorder, value string) bool {
	return bytes.Contains(response.Body.Bytes(), []byte(value))
}
