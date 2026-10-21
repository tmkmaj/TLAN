package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestPrivatePasscodeMembershipAndPowerPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.EnsurePrivateNetwork("Friends", "friends-secret-code", "10.245.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	broker := network.NewRelayBroker(2048)
	defer broker.Close()
	server := httptest.NewServer((&Server{Store: store, AdminToken: "administrator-only", Relay: broker}).Handler())
	defer server.Close()
	identities := make([]clientidentity.Identity, 2)
	apis := make([]*clientapi.Client, 2)
	members := make([]clientapi.Membership, 2)
	for i := range identities {
		identities[i], err = clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.json"))
		if err != nil {
			t.Fatal(err)
		}
		apis[i] = clientapi.New(server.URL, "")
		members[i], err = apis[i].Enroll("friends-secret-code", identities[i].RegisterRequest(), identities[i].PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		apis[i].Token = members[i].Token
		if members[i].Network.ID != n.ID || members[i].Member.VirtualIP == "" {
			t.Fatal("enrollment incomplete")
		}
	}
	if _, err = clientapi.New(server.URL, "").Enroll("wrong-code", identities[0].RegisterRequest(), identities[0].PrivateKey); err == nil {
		t.Fatal("wrong passcode accepted")
	}
	if _, err = apis[0].CreateNetwork("forbidden", "password", "10.246.0.0/24"); err == nil {
		t.Fatal("member created admin network")
	}
	if _, err = apis[0].ListNetworks(); err == nil {
		t.Fatal("member enumerated all networks")
	}
	if _, err = apis[0].Heartbeat(identities[1].DeviceID); err == nil {
		t.Fatal("member changed another member heartbeat")
	}
	if _, err = apis[0].SetForwarding(core.NetworkID(n.ID), identities[1].DeviceID, true); err == nil {
		t.Fatal("member changed another member power")
	}
	if err = apis[0].RemoveDevice(core.NetworkID(n.ID), identities[1].DeviceID); err == nil {
		t.Fatal("member removed another member")
	}
	if _, err = apis[0].SetForwarding(core.NetworkID(n.ID), identities[0].DeviceID, true); err != nil {
		t.Fatal(err)
	}
	list, err := apis[1].ListDevices(core.NetworkID(n.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range list {
		if d.ID == identities[0].DeviceID.String() && !d.Online {
			t.Fatal("power on was not visible")
		}
		if d.ID == identities[1].DeviceID.String() && d.Online {
			t.Fatal("joined but powered off member appeared online")
		}
	}
	if _, err = apis[0].SetForwarding(core.NetworkID(n.ID), identities[0].DeviceID, false); err != nil {
		t.Fatal(err)
	}
	if _, err = apis[0].Heartbeat(identities[0].DeviceID); err != nil {
		t.Fatal(err)
	}
	list, err = apis[1].ListDevices(core.NetworkID(n.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range list {
		if d.ID == identities[0].DeviceID.String() && d.Online {
			t.Fatal("heartbeat re-enabled disabled forwarding")
		}
	}
	// The same passcode cannot be used as an API administrator credential.
	if _, err = clientapi.New(server.URL, "friends-secret-code").ListNetworks(); err == nil {
		t.Fatal("join code accepted as administrator token")
	}
	// Both scoped credentials can obtain and attach their side of a relay.
	ticket, err := apis[0].CreateRelaySession(core.NetworkID(n.ID), identities[0].DeviceID, identities[1].DeviceID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = apis[0].CreateRelaySession(core.NetworkID(n.ID), identities[1].DeviceID, identities[0].DeviceID, time.Minute); err == nil {
		t.Fatal("member impersonated relay source")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayTicket := network.RelayTicket{SessionID: ticket.SessionID, Source: ticket.Source, Target: ticket.Target, Secret: ticket.Secret, ExpiresAt: ticket.ExpiresAt}
	if connection, err := network.DialHTTPRelay(ctx, server.URL, apis[0].Token, relayTicket, identities[1].DeviceID); err == nil {
		connection.Close()
		t.Fatal("member impersonated relay endpoint")
	}
	c1, err := network.DialHTTPRelay(ctx, server.URL, apis[0].Token, relayTicket, identities[0].DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := network.DialHTTPRelay(ctx, server.URL, apis[1].Token, relayTicket, identities[1].DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err = c1.Send([]byte("encrypted-test-data")); err != nil {
		t.Fatal(err)
	}
	packet, err := c2.ReceivePacket()
	if err != nil || string(packet) != "encrypted-test-data" {
		t.Fatal("scoped relay failed")
	}
	// Credential is persisted hashed, survives restart and keeps the same IP.
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.AuthenticateMember(apis[0].Token); !ok {
		t.Fatal("member credential lost on restart")
	}
	n2, err := reopened.EnsurePrivateNetwork("Friends", "new-friends-code", "10.245.0.0/24")
	if err != nil || n2.ID != n.ID {
		t.Fatal("server restart changed network")
	}
	m, err := apis[0].Session()
	if err != nil || m.Member.VirtualIP != members[0].Member.VirtualIP {
		t.Fatal("stable IP/session lost")
	}
	if err = apis[0].RemoveDevice(core.NetworkID(n.ID), identities[0].DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = apis[0].Session(); err == nil {
		t.Fatal("removed member credential remains active")
	}
}

func TestEnrollmentResponseDoesNotContainPlainCredentialAndLimitsAttempts(t *testing.T) {
	store, _ := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	store.EnsurePrivateNetwork("test", "passcode-test", "10.245.0.0/24")
	identity, _ := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.json"))
	service := &Server{Store: store, AdminToken: "admin"}
	body, _ := json.Marshal(map[string]any{"code": "passcode-test", "device": identity.RegisterRequest()})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1000"
	service.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated || strings.Contains(recorder.Body.String(), "member_") || strings.Contains(recorder.Body.String(), "passcode-test") {
		t.Fatal("enrollment exposed plain credential or failed")
	}
	for i := 0; i < 12; i++ {
		service.allowEnrollment(req)
	}
	if service.allowEnrollment(req) {
		t.Fatal("join attempts were not bounded")
	}
}
