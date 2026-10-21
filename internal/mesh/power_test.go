package mesh

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestMemberPowerCyclePreservesAddressAndClosesAdapter(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsurePrivateNetwork("friends", "friends-code", "10.243.0.0/24"); err != nil {
		t.Fatal(err)
	}
	broker := network.NewRelayBroker(4096)
	defer broker.Close()
	server := httptest.NewServer((&control.Server{Store: store, AdminToken: "test-admin", Relay: broker}).Handler())
	defer server.Close()
	identity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := clientapi.New(server.URL, "")
	m, err := api.Enroll("friends-code", identity.RegisterRequest(), identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	api.Token = m.Token
	for cycle := 0; cycle < 2; cycle++ {
		nic := newNIC()
		engine, err := Start(context.Background(), Options{API: api, Identity: identity, Network: m.Network, Member: m.Member, Native: nic, RelayOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = api.SetForwarding(core.NetworkID(m.Network.ID), identity.DeviceID, true); err != nil {
			engine.Close()
			t.Fatal(err)
		}
		list, err := api.ListDevices(core.NetworkID(m.Network.ID))
		if err != nil || len(list) != 1 || !list[0].Online {
			engine.Close()
			t.Fatal("power on was not visible")
		}
		engine.Close()
		if _, err = api.SetForwarding(core.NetworkID(m.Network.ID), identity.DeviceID, false); err != nil {
			t.Fatal(err)
		}
		select {
		case <-nic.done:
		default:
			t.Fatal("power off left adapter open")
		}
		if engine.Status().Running {
			t.Fatal("engine still running after power off")
		}
		list, err = api.ListDevices(core.NetworkID(m.Network.ID))
		if err != nil || len(list) != 1 || list[0].Online {
			t.Fatal("power off was not visible")
		}
		saved, err := api.Session()
		if err != nil || saved.Member.VirtualIP != m.Member.VirtualIP {
			t.Fatal("power cycle changed virtual address")
		}
	}
}
