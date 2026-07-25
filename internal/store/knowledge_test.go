package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestGetProfileIsScopedToScan(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanA, err := db.CreateScan("https://a.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	scanB, err := db.CreateScan("https://b.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	const sharedID = "GET /orders/{id}"
	if err := db.UpsertProfile(scanA, &types.PageProfile{
		ID: sharedID, URL: "https://a.example.test/orders/41", Method: "GET",
		Purpose: "scan A profile",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanB, &types.PageProfile{
		ID: sharedID, URL: "https://b.example.test/orders/99", Method: "GET",
		Purpose: "scan B profile",
	}); err != nil {
		t.Fatal(err)
	}

	profileA, err := db.GetProfile(scanA, sharedID)
	if err != nil {
		t.Fatalf("get scan A profile: %v", err)
	}
	if profileA.Purpose != "scan A profile" || profileA.URL != "https://a.example.test/orders/41" {
		t.Fatalf("scan A returned cross-scan profile: %+v", profileA)
	}

	profileB, err := db.GetProfile(scanB, sharedID)
	if err != nil {
		t.Fatalf("get scan B profile: %v", err)
	}
	if profileB.Purpose != "scan B profile" || profileB.URL != "https://b.example.test/orders/99" {
		t.Fatalf("scan B returned cross-scan profile: %+v", profileB)
	}

	unknownScan := scanB + 1
	if _, err := db.GetProfile(unknownScan, sharedID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get profile from unknown scan error = %v, want sql.ErrNoRows", err)
	}
}

func TestUpsertProfileDisambiguatesSamePathAcrossOrigins(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "profile-origins.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	app := &types.PageProfile{
		ID: "GET /admin", URL: "https://app.example.test/admin", Method: "GET", Purpose: "App route",
	}
	api := &types.PageProfile{
		ID: "GET /admin", URL: "https://api.example.test/admin", Method: "GET", Purpose: "API route",
	}
	if err := db.UpsertProfile(scanID, app); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, api); err != nil {
		t.Fatal(err)
	}
	if api.ID != "GET https://api.example.test/admin" {
		t.Fatalf("qualified profile id = %q", api.ID)
	}

	profiles, err := db.GetAllProfiles(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %+v, want two origin-distinct rows", profiles)
	}
	byID := make(map[string]types.PageProfile, len(profiles))
	for _, profile := range profiles {
		byID[profile.ID] = profile
	}
	if byID["GET /admin"].Purpose != "App route" || byID[api.ID].Purpose != "API route" {
		t.Fatalf("cross-origin semantics were merged: %+v", profiles)
	}

	// A later write arriving with the legacy ID must resolve to the same
	// qualified row instead of creating a third profile or overwriting app.
	apiUpdate := &types.PageProfile{
		ID: "GET /admin", URL: "https://api.example.test/admin", Method: "GET", Purpose: "Updated API route",
	}
	if err := db.UpsertProfile(scanID, apiUpdate); err != nil {
		t.Fatal(err)
	}
	if apiUpdate.ID != api.ID {
		t.Fatalf("repeat qualification = %q, want %q", apiUpdate.ID, api.ID)
	}
	updated, err := db.GetProfile(scanID, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Purpose != "Updated API route" {
		t.Fatalf("qualified profile was not updated: %+v", updated)
	}
}

func TestUpsertProfilePersistsObservedFlags(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "profile-flags.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://api.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID:            "GET /users/v1",
		URL:           "https://api.example.test/users/v1",
		Method:        "GET",
		Purpose:       "User list endpoint",
		HasInput:      true,
		HasFileUpload: true,
		HasAuth:       true,
		HasErrors:     true,
		IsAPI:         true,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetProfile(scanID, "GET /users/v1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasInput || !got.HasFileUpload || !got.HasAuth || !got.HasErrors || !got.IsAPI {
		t.Fatalf("profile flags were not persisted/read back: %+v", got)
	}

	var hasInput, hasUpload, hasAuth, hasErrors, isAPI bool
	if err := db.Conn().QueryRow(`
		SELECT has_input, has_file_upload, has_auth, has_errors, is_api
		FROM page_profiles WHERE scan_id = ? AND id = ?`, scanID, "GET /users/v1",
	).Scan(&hasInput, &hasUpload, &hasAuth, &hasErrors, &isAPI); err != nil {
		t.Fatal(err)
	}
	if !hasInput || !hasUpload || !hasAuth || !hasErrors || !isAPI {
		t.Fatalf("stored flags = input:%v upload:%v auth:%v errors:%v api:%v", hasInput, hasUpload, hasAuth, hasErrors, isAPI)
	}
}

func TestReconModelRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, `{"roles":[{"id":"member","name":"Member"}]}`); err != nil {
		t.Fatal(err)
	}
	raw, err := db.GetReconModel(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if raw != `{"roles":[{"id":"member","name":"Member"}]}` {
		t.Fatalf("recon JSON = %s", raw)
	}
}
