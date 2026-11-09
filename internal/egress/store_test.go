package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	configDir := t.TempDir()
	store, err := NewStore(configDir)
	if err != nil {
		t.Fatalf("NewStore(): %v", err)
	}
	if got, want := store.Root(), filepath.Join(configDir, "egress"); got != want {
		t.Fatalf("Store.Root() = %q, want %q", got, want)
	}
	return store
}

func TestStoreMissingFileLoadsEmpty(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	doc, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if doc.SchemaVersion != SchemaVersion || len(doc.Profiles) != 0 {
		t.Fatalf("Load() = %+v, want empty schema %d document", doc, SchemaVersion)
	}
	if _, err := os.Stat(filepath.Join(store.Root(), profilesFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing profile file stat = %v, want os.ErrNotExist", err)
	}
}

func TestStoreRoundTripAndAtomicWrite(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	doc := ProfilesDocument{SchemaVersion: SchemaVersion, Profiles: []EgressProfile{validProfile()}}
	if err := store.Save(doc); err != nil {
		t.Fatalf("Save(): %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if !reflect.DeepEqual(loaded, doc) {
		t.Fatalf("Load() = %#v, want %#v", loaded, doc)
	}
	tempFiles, err := filepath.Glob(filepath.Join(store.Root(), "*.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("atomic write left temp files: %v", tempFiles)
	}
}

func TestStoreUnknownFieldAndCorruptionAreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"schemaVersion":1,"profiles":[],"unknown":true}`},
		{name: "trailing JSON", data: `{"schemaVersion":1,"profiles":[]} {}`},
		{name: "corrupt JSON", data: `{"schemaVersion":1,`},
		{name: "wrong schema", data: `{"schemaVersion":99,"profiles":[]}`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			if err := os.MkdirAll(store.Root(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Root(), profilesFileName), []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("Load() accepted invalid profile JSON")
			}
		})
	}
}

func TestStoreRejectsDuplicateProfiles(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	first := validProfile()
	second := validProfile()
	doc := ProfilesDocument{SchemaVersion: SchemaVersion, Profiles: []EgressProfile{first, second}}
	err := store.Save(doc)
	if !errors.Is(err, ErrDuplicateProfile) {
		t.Fatalf("Save() error = %v, want ErrDuplicateProfile", err)
	}
}

func TestStoreUpsertFindDelete(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	profile := validProfile()
	stored, err := store.Upsert(profile)
	if err != nil {
		t.Fatalf("Upsert(): %v", err)
	}
	if stored.Version != 1 {
		t.Fatalf("Upsert() version = %d, want 1", stored.Version)
	}
	found, err := store.Find(profile.ID)
	if err != nil {
		t.Fatalf("Find(): %v", err)
	}
	if !reflect.DeepEqual(found, stored) {
		t.Fatalf("Find() = %#v, want %#v", found, stored)
	}

	profile.Name = "Work Updated"
	profile.Version = 2
	updated, err := store.Upsert(profile)
	if err != nil {
		t.Fatalf("Upsert(update): %v", err)
	}
	if updated.Name != "Work Updated" || updated.Version != 2 {
		t.Fatalf("Upsert(update) = %+v", updated)
	}
	if err := store.Delete(profile.ID); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	if _, err := store.Find(profile.ID); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Find(deleted) error = %v, want ErrProfileNotFound", err)
	}
	if err := store.Delete(profile.ID); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Delete(deleted) error = %v, want ErrProfileNotFound", err)
	}
}

func TestStoreConcurrentUpserts(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	const count = 12
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			profile := validProfile()
			profile.ID = fmt.Sprintf("work-%02d", i)
			profile.Name = fmt.Sprintf("Work %02d", i)
			profile.Rules[0].ID = fmt.Sprintf("rule-%02d", i)
			profile.Rules[0].Name = fmt.Sprintf("Rule %02d", i)
			profile.Rules[0].ExePath = fmt.Sprintf(`C:\Program Files\Example\app-%02d.exe`, i)
			profile.Version = 1
			if _, err := store.Upsert(profile); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Upsert(): %v", err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if len(doc.Profiles) != count {
		t.Fatalf("stored profiles = %d, want %d", len(doc.Profiles), count)
	}
}

func TestSecretRoundTripDoesNotExposePlaintext(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI plaintext check is Windows-specific")
	}

	store := newTestStore(t)
	const ref = "gateway-credential"
	secret := "super-secret-token-123"
	if err := store.SetSecret(ref, secret); err != nil {
		t.Fatalf("SetSecret(): %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(store.Root(), secretsFileName))
	if err != nil {
		t.Fatalf("read secrets file: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("secrets file contains the plaintext secret")
	}
	if !strings.Contains(string(raw), "dpapi:") {
		t.Fatal("secrets file is not DPAPI protected")
	}
	got, err := store.GetSecret(ref)
	if err != nil {
		t.Fatalf("GetSecret(): %v", err)
	}
	if got != secret {
		t.Fatalf("GetSecret() = %q, want %q", got, secret)
	}
	has, err := store.HasSecret(ref)
	if err != nil || !has {
		t.Fatalf("HasSecret() = %v, %v; want true, nil", has, err)
	}
	if err := store.DeleteSecret(ref); err != nil {
		t.Fatalf("DeleteSecret(): %v", err)
	}
	if _, err := store.GetSecret(ref); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("GetSecret(deleted) error = %v, want ErrSecretNotFound", err)
	}
}

func TestSecretCorruptionAndIDValidation(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := os.MkdirAll(store.Root(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Root(), secretsFileName), []byte(`{"schemaVersion":1,"secrets":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSecret("valid-ref"); err == nil {
		t.Fatal("GetSecret() accepted corrupt secrets file")
	}

	for _, ref := range []string{"", "../escape", "space ref", "slash/ref", strings.Repeat("a", 65)} {
		if err := store.SetSecret(ref, "value"); !errors.Is(err, ErrInvalidID) {
			t.Errorf("SetSecret(%q) error = %v, want ErrInvalidID", ref, err)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	t.Parallel()

	input := "token=short token-longer lease=lease-secret"
	got := RedactSecrets(input, "short", "token-longer", "lease-secret")
	if strings.Contains(got, "short") || strings.Contains(got, "token-longer") || strings.Contains(got, "lease-secret") {
		t.Fatalf("RedactSecrets() leaked a secret: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("RedactSecrets() = %q, want redaction marker", got)
	}
}

func TestStoreUpsertAssignsVersion(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	profile := validProfile()
	profile.Version = 0
	first, err := store.Upsert(profile)
	if err != nil {
		t.Fatalf("first Upsert(): %v", err)
	}
	if first.Version != 1 {
		t.Fatalf("first version = %d, want 1", first.Version)
	}
	profile.Version = 0
	second, err := store.Upsert(profile)
	if err != nil {
		t.Fatalf("second Upsert(): %v", err)
	}
	if second.Version != 2 {
		t.Fatalf("second version = %d, want 2", second.Version)
	}
}
