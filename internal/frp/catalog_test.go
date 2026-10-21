package frp

import "testing"

func TestCatalogKeepsProfilesIndependent(t *testing.T) {
	catalog, err := NewCatalog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defaultStore, _ := catalog.Store(DefaultProfileID)
	cfg := testConfig(t)
	if _, err = defaultStore.Save(cfg, "token-default"); err != nil {
		t.Fatal(err)
	}
	info, err := catalog.Create("office", "办公室穿透")
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "office" {
		t.Fatalf("created profile = %+v", info)
	}
	officeStore, _ := catalog.Store("office")
	cfg = testConfig(t)
	cfg.Profile.ID = "office"
	cfg.Profile.Name = "办公室穿透"
	if _, err = officeStore.Save(cfg, "token-office"); err != nil {
		t.Fatal(err)
	}
	profiles, err := catalog.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].ID != DefaultProfileID || profiles[1].ID != "office" || !profiles[1].Configured {
		t.Fatalf("profiles = %+v", profiles)
	}
	if token, _ := defaultStore.Token(DefaultCredential); token != "token-default" {
		t.Fatalf("default token = %q", token)
	}
	if token, _ := officeStore.Token(DefaultCredential); token != "token-office" {
		t.Fatalf("office token = %q", token)
	}
}
