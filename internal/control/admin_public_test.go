package control

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestAdminEnrollmentAndClientAdminAPI(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.EnsurePrivateNetwork("Admin Client", "TmkNetwork", "10.244.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: store, AdminToken: "Tmkmaj233"}).Handler())
	defer server.Close()

	adminIdentity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "admin-id.json"))
	if err != nil {
		t.Fatal(err)
	}
	memberAPI := clientapi.New(server.URL, "")
	adminMembership, err := memberAPI.Enroll("Tmkmaj233", adminIdentity.RegisterRequest(), adminIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !adminMembership.Admin || adminMembership.Network.ID != network.ID {
		t.Fatalf("admin enrollment = %+v", adminMembership)
	}
	memberAPI.Token = adminMembership.Token
	if _, err := memberAPI.Session(); err != nil {
		t.Fatalf("admin member session failed: %v", err)
	}

	normalIdentity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "normal-id.json"))
	if err != nil {
		t.Fatal(err)
	}
	normalAPI := clientapi.New(server.URL, "")
	normalMembership, err := normalAPI.Enroll("TmkNetwork", normalIdentity.RegisterRequest(), normalIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if normalMembership.Admin {
		t.Fatal("normal enrollment was marked admin")
	}

	adminAPI := clientapi.NewAdmin(server.URL, "Tmkmaj233")
	overview, err := adminAPI.Overview()
	if err != nil {
		t.Fatal(err)
	}
	if overview.MemberCount != 2 || overview.Network.ID != network.ID {
		t.Fatalf("admin overview = %+v", overview)
	}
	members, err := adminAPI.Members()
	if err != nil {
		t.Fatal(err)
	}
	if len(members.Members) != 2 {
		t.Fatalf("admin members = %+v", members.Members)
	}
	renamed, err := adminAPI.RenameMember(normalIdentity.DeviceID.String(), "Renamed Member")
	if err != nil || renamed.Name != "Renamed Member" {
		t.Fatalf("rename = %+v, err=%v", renamed, err)
	}
	if err := adminAPI.DisconnectMember(normalIdentity.DeviceID.String()); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if err := adminAPI.KickMember(normalIdentity.DeviceID.String()); err != nil {
		t.Fatalf("kick: %v", err)
	}
	if err := adminAPI.BanMember(normalIdentity.DeviceID.String()); err != nil {
		t.Fatalf("ban: %v", err)
	}
	if _, err := adminAPI.UnbanMember(normalIdentity.DeviceID.String()); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if _, err := clientapi.NewAdmin(server.URL, normalMembership.Token).Overview(); err == nil {
		t.Fatal("member credential accessed public admin API")
	} else {
		var apiErr *clientapi.AdminAPIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
			t.Fatalf("member admin API error = %v", err)
		}
	}
	if _, err := clientapi.NewAdmin(server.URL, "wrong-admin-token").Overview(); err == nil {
		t.Fatal("wrong admin token accessed public admin API")
	}
}
