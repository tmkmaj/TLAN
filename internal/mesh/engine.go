package mesh

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/platform"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Options struct {
	API           *clientapi.Client
	Identity      clientidentity.Identity
	Network       clientapi.Network
	Member        clientapi.Device
	InterfaceName string
	STUNServer    string
	RelayOnly     bool
	TrustedRoots  *x509.CertPool
	// Native is injectable for end-to-end tests without installing a driver.
	Native tun.Device
	// Ledger, Cleaner, Runner and InstanceID are injectable for recovery tests.
	// Production uses the user-private platform ledger and system cleaner.
	Ledger     platform.ResourceLedger
	Cleaner    platform.Cleaner
	Runner     platform.Runner
	InstanceID string
}
type PeerStatus struct {
	Reachable          bool
	ID, Name, IP, Path string
	Handshake          time.Time
	RTT                time.Duration
}
type Status struct {
	Running                 bool
	Address                 string
	Peers                   []PeerStatus
	Sent, Received, Dropped uint64
	LastError               string
}
type Engine struct {
	options          Options
	native           tun.Device
	plain            *tunnel
	bind             *meshBind
	wg               *device.Device
	ctx              context.Context
	cancel           context.CancelFunc
	once             sync.Once
	wgLoops          sync.WaitGroup
	mu               sync.RWMutex
	peers            map[string]clientapi.Device
	dialing          map[string]bool
	lastError        string
	candidates       []core.Candidate
	closed           bool
	generation       uint64
	generationMu     sync.Mutex
	generationDone   chan struct{}
	generationClosed bool
	closeErr         error
	instanceID       string
	ledger           platform.ResourceLedger
	cleaner          platform.Cleaner
	recovery         platform.RecoveryStatus
	transport        []platform.ResourceRecord
	cleanupError     string
}

func Start(parent context.Context, options Options) (*Engine, error) {
	if parent == nil {
		return nil, errors.New("context is required")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if options.API == nil {
		return nil, errors.New("control API is required")
	}
	if err := options.Identity.Validate(); err != nil {
		return nil, err
	}
	if core.NetworkID(options.Network.ID).Validate() != nil {
		return nil, errors.New("invalid network ID")
	}
	prefix, err := netip.ParsePrefix(options.Network.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return nil, errors.New("invalid network CIDR")
	}
	local, err := netip.ParseAddr(options.Member.VirtualIP)
	if err != nil || !prefix.Contains(local) {
		return nil, errors.New("assigned virtual IP is outside network")
	}
	if options.Member.ID != options.Identity.DeviceID.String() {
		return nil, errors.New("membership identity mismatch")
	}
	ctx, cancel := context.WithCancel(parent)
	apiCopy := *options.API
	apiCopy.Context = ctx
	options.API = &apiCopy
	instanceID := options.InstanceID
	if instanceID == "" {
		instanceID, err = platform.NewInstanceID()
		if err != nil {
			cancel()
			return nil, err
		}
	}
	ledger := options.Ledger
	if ledger == nil {
		if options.Native != nil {
			ledger = platform.NewMemoryLedger()
		} else {
			ledger, err = platform.OpenDefaultLedger()
			if err != nil {
				cancel()
				return nil, fmt.Errorf("open Mesh resource ledger: %w", err)
			}
		}
	}
	cleaner := options.Cleaner
	if cleaner == nil {
		if options.Runner != nil {
			cleaner = func(record platform.ResourceRecord) error {
				return platform.CleanupResourceWithRunner(record, options.Runner)
			}
		} else {
			cleaner = platform.CleanupResource
		}
	}
	recovery := ledger.Recover(instanceID, cleaner)
	e := &Engine{
		options: options, ctx: ctx, cancel: cancel,
		peers: make(map[string]clientapi.Device), dialing: make(map[string]bool),
		generation: 1, generationDone: make(chan struct{}),
		instanceID: instanceID, ledger: ledger, cleaner: cleaner, recovery: recovery,
	}
	e.plain = newTunnel(local, prefix)
	e.bind, err = newBind(local, options.Network.ID, options.Identity.PrivateKey)
	if err != nil {
		cancel()
		return nil, err
	}
	e.bind.relayOnly = options.RelayOnly
	e.native = options.Native
	if e.native == nil {
		e.native, err = platform.OpenTunnelWithOptions(options.InterfaceName, netip.PrefixFrom(local, prefix.Bits()), MTU, platform.TunnelOptions{
			InstanceID: instanceID,
			Ledger:     ledger,
			Cleaner:    cleaner,
			Runner:     options.Runner,
		})
		if err != nil {
			cancel()
			if recovery.HasIssues() {
				return nil, fmt.Errorf("%w; prior Mesh resource recovery incomplete: failed=%d unproven=%d", err, recovery.Failed, recovery.Unproven)
			}
			return nil, err
		}
		if _, err = meshInterfaceIndex(options.InterfaceName); err != nil {
			if closeErr := e.Close(); closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
			return nil, err
		}
	}
	e.wgLoops.Add(1)
	go func() {
		defer e.wgLoops.Done()
		for range e.native.Events() {
		}
	}()
	e.wg = device.NewDevice(e.plain, e.bind, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(format string, args ...any) { e.setError(fmt.Errorf(format, args...)) }})
	private, _ := base64.StdEncoding.DecodeString(options.Identity.PrivateKey)
	if err = e.wg.IpcSet("private_key=" + hex.EncodeToString(private) + "\n"); err != nil {
		return nil, closeStartError(e, err)
	}
	if err = e.wg.Up(); err != nil {
		return nil, closeStartError(e, err)
	}
	e.gatherCandidates()
	if _, err = options.API.SetCandidates(core.NetworkID(options.Network.ID), options.Identity.DeviceID, e.candidates); err != nil {
		return nil, closeStartError(e, err)
	}
	if err = e.syncPeers(); err != nil {
		return nil, closeStartError(e, err)
	}
	if err = e.registerTransportResources(); err != nil {
		if closeErr := e.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}
	e.wgLoops.Add(4)
	go e.readNative()
	go e.writeNative()
	go e.controlLoop()
	go func() {
		defer e.wgLoops.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		e.plain.probePeers()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-ticker.C:
				e.plain.probePeers()
			}
		}
	}()
	go func() { <-ctx.Done(); e.Close() }()
	return e, nil
}

func closeStartError(e *Engine, cause error) error {
	if closeErr := e.Close(); closeErr != nil {
		return errors.Join(cause, closeErr)
	}
	return cause
}

func (e *Engine) setError(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.lastError = err.Error()
	e.mu.Unlock()
}
func (e *Engine) Close() error {
	e.once.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
		e.closeGeneration()
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		var errs []error
		if e.native != nil {
			errs = append(errs, e.native.Close())
		}
		if e.wg != nil {
			e.wg.Close()
		} else if e.plain != nil {
			errs = append(errs, e.plain.Close())
		}
		e.wgLoops.Wait()
		if err := e.closeTransportResources(); err != nil {
			errs = append(errs, err)
		}
		e.closeErr = errors.Join(errs...)
		if e.closeErr != nil {
			e.setError(e.closeErr)
			e.mu.Lock()
			e.cleanupError = e.closeErr.Error()
			e.mu.Unlock()
		}
	})
	return e.closeErr
}
func (e *Engine) generationChannel() <-chan struct{} {
	e.generationMu.Lock()
	defer e.generationMu.Unlock()
	if e.generationDone == nil {
		return e.ctx.Done()
	}
	return e.generationDone
}

func (e *Engine) advanceGeneration() {
	e.generationMu.Lock()
	defer e.generationMu.Unlock()
	if e.generationClosed || e.generationDone == nil {
		return
	}
	close(e.generationDone)
	e.generation++
	e.generationDone = make(chan struct{})
}

func (e *Engine) closeGeneration() {
	e.generationMu.Lock()
	defer e.generationMu.Unlock()
	if !e.generationClosed && e.generationDone != nil {
		close(e.generationDone)
	}
	e.generationClosed = true
}
func (e *Engine) readNative() {
	defer e.wgLoops.Done()
	bufs := [][]byte{make([]byte, 65536)}
	sizes := make([]int, 1)
	for {
		n, err := e.native.Read(bufs, sizes, 0)
		if err != nil {
			if e.ctx.Err() == nil {
				e.setError(err)
				go e.Close()
			}
			return
		}
		for i := 0; i < n; i++ {
			e.plain.submit(bufs[i][:sizes[i]])
		}
	}
}
func (e *Engine) writeNative() {
	defer e.wgLoops.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case packet := <-e.plain.in:
			if _, err := e.native.Write([][]byte{packet}, 0); err != nil {
				e.setError(err)
			}
		}
	}
}
