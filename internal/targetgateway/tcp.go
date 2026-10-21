package targetgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type tcpPair struct {
	client       net.Conn
	backend      net.Conn
	once         sync.Once
	lastActivity atomic.Int64
}

func (p *tcpPair) close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		if p.client != nil {
			_ = p.client.Close()
		}
		if p.backend != nil {
			_ = p.backend.Close()
		}
	})
}

type copyResult struct {
	clientToBackend bool
	err             error
}

func (g *Gateway) handleTCP(client *net.TCPConn) {
	defer client.Close()
	initial, err := acquireLease(g.ctx, g.cfg.Lease, g.cfg.Target)
	if err != nil {
		g.recordLeaseRejection(err)
		g.stats.tcpRejected.Add(1)
		return
	}

	ctx, cancel := context.WithCancel(g.ctx)
	guard := newLeaseGuard(g.cfg.Lease, g.cfg.Target, initial, g.cfg.LeasePollInterval)
	go guard.watch(ctx)
	defer func() {
		cancel()
		guard.wait()
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, g.cfg.DialTimeout)
	backend, err := g.cfg.Dialer.DialTCP(dialCtx, g.cfg.Target, initial.Generation)
	dialCancel()
	if err != nil {
		if ctx.Err() == nil {
			g.stats.dialFailure.Add(1)
			g.stats.tcpRejected.Add(1)
		}
		return
	}
	if backend == nil {
		g.stats.dialFailure.Add(1)
		g.stats.tcpRejected.Add(1)
		return
	}
	if err := guard.check(ctx); err != nil {
		g.recordLeaseRejection(err)
		_ = backend.Close()
		g.stats.tcpRejected.Add(1)
		return
	}

	pair := &tcpPair{client: client, backend: backend}
	pair.touch()
	if !g.registerPair(pair) {
		pair.close()
		return
	}
	defer g.removePair(pair)
	defer pair.close()

	stopClose := make(chan struct{})
	defer close(stopClose)
	go func() {
		interval := g.cfg.IdleTimeout / 4
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
		if interval > time.Second {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopClose:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, pair.lastActivity.Load())) >= g.cfg.IdleTimeout {
					pair.close()
					return
				}
			}
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			pair.close()
		case <-guard.Invalid():
			pair.close()
		case <-stopClose:
		}
	}()

	results := make(chan copyResult, 2)
	go func() {
		results <- copyResult{clientToBackend: true, err: g.copyStream(ctx, guard, client, backend, true, &pair.lastActivity)}
	}()
	go func() {
		results <- copyResult{clientToBackend: false, err: g.copyStream(ctx, guard, backend, client, false, &pair.lastActivity)}
	}()

	first := <-results
	if first.err != nil {
		pair.close()
	} else if first.clientToBackend {
		closeWrite(backend)
	} else {
		closeWrite(client)
	}
	<-results
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func (g *Gateway) copyStream(ctx context.Context, guard *leaseGuard, src, dst net.Conn, clientToBackend bool, lastActivity *atomic.Int64) error {
	buffer := make([]byte, 32*1024)
	for {
		if err := guard.check(ctx); err != nil {
			return err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			lastActivity.Store(time.Now().UnixNano())
			if err := guard.check(ctx); err != nil {
				return err
			}
			_ = dst.SetWriteDeadline(time.Now().Add(g.cfg.WriteTimeout))
			written, writeErr := writeAll(dst, buffer[:n])
			if written > 0 {
				if clientToBackend {
					g.stats.bytesTo.Add(uint64(written))
				} else {
					g.stats.bytesFrom.Add(uint64(written))
				}
			}
			if writeErr != nil {
				return writeErr
			}
			if err := guard.check(ctx); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return readErr
		}
	}
}

func writeAll(conn net.Conn, data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			total += n
			data = data[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (p *tcpPair) touch() {
	p.lastActivity.Store(time.Now().UnixNano())
}
