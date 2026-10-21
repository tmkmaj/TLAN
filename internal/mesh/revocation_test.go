package mesh

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestControlFailureLifecycle(t *testing.T) {
	for _, status := range []int{401, 403, 404, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.EnsurePrivateNetwork("friends", "friends-code", "10.243.0.0/24"); err != nil {
				t.Fatal(err)
			}
			handler := (&control.Server{Store: store}).Handler()
			var fail atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fail.Load() && strings.HasSuffix(r.URL.Path, "/heartbeat") && status != 401 {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"error":"control failure"}`))
					return
				}
				handler.ServeHTTP(w, r)
			}))
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
			nic := newNIC()
			engine, err := Start(context.Background(), Options{API: api, Identity: identity, Network: m.Network, Member: m.Member, Native: nic, RelayOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			if status == 401 {
				if err := store.RemoveDevice(m.Network.ID, m.Member.ID); err != nil {
					t.Fatal(err)
				}
			}
			fail.Store(true)
			deadline := time.Now().Add(7 * time.Second)
			for time.Now().Before(deadline) && engine.Status().LastError == "" {
				time.Sleep(10 * time.Millisecond)
			}
			if engine.Status().LastError == "" {
				t.Fatal("heartbeat failure was not observed")
			}
			if status == 503 {
				if !engine.Status().Running {
					t.Fatal("temporary outage stopped the engine")
				}
				return
			}
			select {
			case <-nic.done:
			case <-time.After(time.Second):
				t.Fatal("invalid membership left adapter and forwarding active")
			}
		})
	}
}
