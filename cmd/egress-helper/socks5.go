package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

const (
	socks5Version = byte(5)
	socksAuthNone = byte(0x00)
	socksAuthUser = byte(0x02)
	socksNoAuth   = byte(0xff)

	socksCmdConnect      = byte(0x01)
	socksCmdBind         = byte(0x02)
	socksCmdUDPAssociate = byte(0x03)

	socksATYPIPv4   = byte(0x01)
	socksATYPDomain = byte(0x03)
	socksATYPIPv6   = byte(0x04)

	socksReplySucceeded        = byte(0x00)
	socksReplyGeneralFailure   = byte(0x01)
	socksReplyCommandRejected  = byte(0x07)
	socksReplyAddressType      = byte(0x08)
	socksHandshakeTimeout      = 10 * time.Second
	maxSOCKS5UDPPacketSize     = 65535
	maxSOCKS5CredentialLength  = 255
	maxSOCKS5DomainLength      = 255
	maxProxyConnectionsAllowed = 65535
)

var (
	errProxyNotReady        = errors.New("egress helper proxy is not ready")
	errNonLoopbackPeer      = errors.New("SOCKS5 peer is not loopback")
	errSocksAuthentication  = errors.New("SOCKS5 authentication failed")
	errSocksAuthFailed      = errSocksAuthentication
	errSocksCommand         = errors.New("SOCKS5 command is not supported")
	errSocksAddressType     = errors.New("SOCKS5 address type is not supported")
	errSOCKSProtocol        = errors.New("invalid SOCKS5 protocol message")
	errUDPAssociationActive = errors.New("another UDP association is already active")
	errSOCKS5UDPPacket      = errors.New("invalid SOCKS5 UDP packet")
)

type readinessSnapshot struct {
	Ready     bool
	State     egress.EgressState
	LastError string
}

type socksAuthenticator struct {
	enabled      bool
	usernameHash [32]byte
	passwordHash [32]byte
}

func newSOCKSAuthenticator(username, password string) socksAuthenticator {
	if username == "" {
		return socksAuthenticator{}
	}
	return socksAuthenticator{
		enabled:      true,
		usernameHash: sha256.Sum256([]byte(username)),
		passwordHash: sha256.Sum256([]byte(password)),
	}
}

func (a socksAuthenticator) verify(username, password string) bool {
	if !a.enabled {
		return true
	}
	gotUser := sha256.Sum256([]byte(username))
	gotPassword := sha256.Sum256([]byte(password))
	userOK := subtle.ConstantTimeCompare(a.usernameHash[:], gotUser[:])
	passwordOK := subtle.ConstantTimeCompare(a.passwordHash[:], gotPassword[:])
	return userOK&passwordOK == 1
}

type proxy struct {
	cfg    proxyConfig
	tunnel tunnelSession
	auth   socksAuthenticator

	status  atomic.Pointer[readinessSnapshot]
	nextID  atomic.Uint32
	slots   chan struct{}
	udpBusy atomic.Bool

	listenerMu sync.Mutex
	listener   net.Listener

	mu       sync.Mutex
	active   map[net.Conn]struct{}
	failed   bool
	failure  error
	done     chan struct{}
	failOnce sync.Once

	udpListen func(network string, address *net.UDPAddr) (net.PacketConn, error)
}

func newProxy(cfg proxyConfig, tunnel tunnelSession) (*proxy, error) {
	if tunnel == nil {
		return nil, errors.New("egress tunnel is required")
	}
	if cfg.Capability == "" {
		return nil, errors.New("egress capability is required")
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > maxProxyConnectionsAllowed {
		return nil, fmt.Errorf("max connections must be between 1 and %d", maxProxyConnectionsAllowed)
	}
	if cfg.Username == "" && cfg.Password != "" {
		return nil, errors.New("password requires a username")
	}
	if cfg.Username != "" && cfg.Password == "" {
		return nil, errors.New("username requires a password")
	}
	p := &proxy{
		cfg:    cfg,
		tunnel: tunnel,
		auth:   newSOCKSAuthenticator(cfg.Username, cfg.Password),
		slots:  make(chan struct{}, cfg.MaxConnections),
		active: make(map[net.Conn]struct{}),
		done:   make(chan struct{}),
		udpListen: func(network string, address *net.UDPAddr) (net.PacketConn, error) {
			return net.ListenUDP(network, address)
		},
	}
	p.status.Store(&readinessSnapshot{Ready: false, State: egress.StateStopped})
	return p, nil
}

func (p *proxy) markReady() {
	p.status.Store(&readinessSnapshot{Ready: true, State: egress.StateRunning})
}

func (p *proxy) markFailed(err error) {
	if err == nil {
		err = errSessionUnavailable
	}
	p.status.Store(&readinessSnapshot{Ready: false, State: egress.StateError, LastError: err.Error()})
	p.failOnce.Do(func() {
		p.mu.Lock()
		p.failed = true
		p.failure = err
		connections := make([]net.Conn, 0, len(p.active))
		for conn := range p.active {
			connections = append(connections, conn)
		}
		listener := p.listener
		close(p.done)
		p.mu.Unlock()

		if listener != nil {
			_ = listener.Close()
		}
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
}

func (p *proxy) updateReadiness(snapshot egress.EgressSnapshot) {
	for {
		current := p.status.Load()
		if current == nil || !current.Ready {
			return
		}
		next := &readinessSnapshot{Ready: true, State: snapshot.State, LastError: snapshot.LastError}
		if p.status.CompareAndSwap(current, next) {
			return
		}
	}
}

func (p *proxy) isReady() bool {
	snapshot := p.status.Load()
	return snapshot != nil && snapshot.Ready
}

func (p *proxy) failureError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failure
}

func (p *proxy) setListener(listener net.Listener) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed {
		return p.failure
	}
	p.listener = listener
	return nil
}

func (p *proxy) acquireSlot() bool {
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *proxy) releaseSlot() { <-p.slots }

func (p *proxy) addConnection(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || !p.isReady() {
		return false
	}
	p.active[conn] = struct{}{}
	return true
}

func (p *proxy) removeConnection(conn net.Conn) {
	p.mu.Lock()
	delete(p.active, conn)
	p.mu.Unlock()
}

func (p *proxy) serve(ctx context.Context, listener net.Listener) error {
	if err := p.setListener(listener); err != nil {
		return err
	}
	if ctx != nil {
		stopAfter := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stopAfter()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil
			}
			if failure := p.failureError(); failure != nil {
				return failure
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept SOCKS5 connection: %w", err)
		}
		if !p.isReady() || !p.acquireSlot() {
			_ = conn.Close()
			continue
		}
		if !p.addConnection(conn) {
			p.releaseSlot()
			_ = conn.Close()
			continue
		}
		go func() {
			defer p.releaseSlot()
			defer p.removeConnection(conn)
			defer conn.Close()
			if ctx == nil {
				ctx = context.Background()
			}
			_ = p.handleConn(ctx, conn)
		}()
	}
}

func (p *proxy) handleConn(ctx context.Context, conn net.Conn) error {
	if !isLoopbackAddr(conn.RemoteAddr()) {
		_ = conn.Close()
		return errNonLoopbackPeer
	}
	if !p.isReady() {
		_ = conn.Close()
		return errProxyNotReady
	}
	if err := conn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return fmt.Errorf("set SOCKS5 handshake deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	if err := p.performGreeting(conn); err != nil {
		return err
	}
	if err := p.performAuthentication(conn); err != nil {
		return err
	}

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("read SOCKS5 request header: %w", err)
	}
	if header[0] != socks5Version || header[2] != 0 {
		return errSOCKSProtocol
	}
	command := header[1]
	if command != socksCmdConnect && command != socksCmdUDPAssociate {
		if isSupportedSOCKSAddressType(header[3]) {
			_, _, _ = readSOCKS5AddressBody(conn, header[3])
		}
		_ = writeSOCKS5Reply(conn, socksReplyCommandRejected, nil)
		return fmt.Errorf("%w: command %#x", errSocksCommand, command)
	}
	host, port, err := readSOCKS5AddressBody(conn, header[3])
	if err != nil {
		if errors.Is(err, errSocksAddressType) {
			_ = writeSOCKS5Reply(conn, socksReplyAddressType, nil)
		} else {
			_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		}
		return err
	}
	if !p.isReady() {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		return errProxyNotReady
	}

	switch command {
	case socksCmdConnect:
		return p.handleConnect(conn, egress.OpenTarget{Host: host, Port: port, Protocol: egress.ProtocolTCP})
	case socksCmdUDPAssociate:
		return p.handleUDPAssociate(ctx, conn, egress.OpenTarget{Host: host, Port: port, Protocol: egress.ProtocolUDP})
	default:
		_ = writeSOCKS5Reply(conn, socksReplyCommandRejected, nil)
		return errSocksCommand
	}
}

func (p *proxy) performGreeting(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if header[0] != socks5Version || header[1] == 0 {
		return errSOCKSProtocol
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read SOCKS5 methods: %w", err)
	}
	wanted := socksAuthNone
	if p.auth.enabled {
		wanted = socksAuthUser
	}
	for _, method := range methods {
		if method == wanted {
			if err := writeFull(conn, []byte{socks5Version, wanted}); err != nil {
				return fmt.Errorf("write SOCKS5 method: %w", err)
			}
			return nil
		}
	}
	_ = writeFull(conn, []byte{socks5Version, socksNoAuth})
	return errSocksAuthentication
}

func (p *proxy) performAuthentication(conn net.Conn) error {
	if !p.auth.enabled {
		return nil
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("read SOCKS5 authentication header: %w", err)
	}
	if header[0] != 1 || header[1] == 0 {
		_ = writeFull(conn, []byte{1, 1})
		return errSocksAuthentication
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read SOCKS5 username: %w", err)
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return fmt.Errorf("read SOCKS5 password length: %w", err)
	}
	if passwordLength[0] == 0 {
		_ = writeFull(conn, []byte{1, 1})
		return errSocksAuthentication
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read SOCKS5 password: %w", err)
	}
	if !p.auth.verify(string(username), string(password)) {
		_ = writeFull(conn, []byte{1, 1})
		return errSocksAuthentication
	}
	if err := writeFull(conn, []byte{1, 0}); err != nil {
		return fmt.Errorf("write SOCKS5 authentication result: %w", err)
	}
	return nil
}

func (p *proxy) handleConnect(conn net.Conn, target egress.OpenTarget) error {
	if err := target.Validate(); err != nil {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		return err
	}
	streamID := p.nextID.Add(1)
	if streamID == 0 {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		return errors.New("SOCKS5 stream ID space exhausted")
	}
	stream, err := p.tunnel.OpenStream(streamID)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		p.markFailed(fmt.Errorf("open egress stream: %w", err))
		return err
	}
	if err := egress.WriteTargetPreamble(stream, target); err != nil {
		_ = stream.Close()
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		p.markFailed(fmt.Errorf("write egress target preamble: %w", err))
		return err
	}
	if err := writeSOCKS5Reply(conn, socksReplySucceeded, nil); err != nil {
		_ = stream.Close()
		return fmt.Errorf("write SOCKS5 CONNECT reply: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	if err := copyBidirectional(conn, stream); err != nil {
		p.markFailed(fmt.Errorf("CONNECT stream failed: %w", err))
		return err
	}
	return nil
}

func copyBidirectional(conn net.Conn, stream tunnelStream) error {
	results := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, conn)
		_ = stream.CloseWrite()
		results <- err
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		closeWrite(conn)
		results <- err
	}()
	first := <-results
	if first != nil {
		return first
	}
	return <-results
}

func closeWrite(writer any) {
	if halfCloser, ok := writer.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

func (p *proxy) forwardSOCKS5UDPDatagram(ctx context.Context, packet []byte) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if !p.isReady() {
		return errProxyNotReady
	}
	target, payload, err := parseSOCKS5UDPPacket(packet)
	if err != nil {
		return fmt.Errorf("%w: %v", errSOCKS5UDPPacket, err)
	}
	envelope, err := egress.EncodeDatagram(target, payload)
	if err != nil {
		return fmt.Errorf("%w: %v", errSOCKS5UDPPacket, err)
	}
	if err := p.tunnel.SendDatagram(envelope); err != nil {
		return fmt.Errorf("send egress datagram: %w", err)
	}
	return nil
}
func (p *proxy) handleUDPAssociate(ctx context.Context, conn net.Conn, _ egress.OpenTarget) error {
	if !p.udpBusy.CompareAndSwap(false, true) {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		return errUDPAssociationActive
	}
	defer p.udpBusy.Store(false)

	listenIP := loopbackIPFromAddress(p.cfg.ListenAddr)
	if listenIP == nil {
		listenIP = net.IPv4(127, 0, 0, 1)
	}
	udpConn, err := p.udpListen("udp", &net.UDPAddr{IP: listenIP, Port: 0})
	if err != nil {
		_ = writeSOCKS5Reply(conn, socksReplyGeneralFailure, nil)
		return fmt.Errorf("create SOCKS5 UDP relay: %w", err)
	}
	defer udpConn.Close()
	if err := writeSOCKS5Reply(conn, socksReplySucceeded, udpConn.LocalAddr()); err != nil {
		return fmt.Errorf("write SOCKS5 UDP ASSOCIATE reply: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return p.relayUDP(ctx, conn, udpConn)
}

func (p *proxy) relayUDP(ctx context.Context, control net.Conn, udpConn net.PacketConn) error {
	if ctx == nil {
		ctx = context.Background()
	}
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientIP := addressIP(control.RemoteAddr())
	if clientIP == nil || !clientIP.IsLoopback() {
		return errNonLoopbackPeer
	}

	var clientMu sync.Mutex
	var clientUDP net.Addr
	errorsCh := make(chan error, 3)

	stopOnContext := context.AfterFunc(relayCtx, func() { _ = udpConn.Close() })
	defer stopOnContext()

	go func() {
		for {
			frame, err := p.tunnel.ReceiveDatagram(relayCtx)
			if err != nil {
				if relayCtx.Err() == nil {
					errorsCh <- fmt.Errorf("receive egress datagram: %w", err)
				}
				return
			}
			target, payload, err := egress.DecodeDatagram(frame)
			if err != nil {
				if relayCtx.Err() == nil {
					errorsCh <- fmt.Errorf("decode egress datagram: %w", err)
				}
				return
			}
			clientMu.Lock()
			destination := clientUDP
			clientMu.Unlock()
			if destination == nil {
				continue
			}
			packet, err := encodeSOCKS5UDPPacket(target.Host, target.Port, payload)
			if err != nil {
				continue
			}
			if _, err := udpConn.WriteTo(packet, destination); err != nil {
				if relayCtx.Err() == nil {
					errorsCh <- fmt.Errorf("write SOCKS5 UDP relay: %w", err)
				}
				return
			}
		}
	}()

	go func() {
		buffer := make([]byte, maxSOCKS5UDPPacketSize)
		for {
			count, source, err := udpConn.ReadFrom(buffer)
			if err != nil {
				if relayCtx.Err() == nil {
					errorsCh <- fmt.Errorf("read SOCKS5 UDP relay: %w", err)
				}
				return
			}
			if !isLoopbackAddr(source) {
				continue
			}
			sourceIP := addressIP(source)
			if sourceIP == nil || !sourceIP.Equal(clientIP) {
				continue
			}
			clientMu.Lock()
			if clientUDP == nil {
				clientUDP = cloneAddr(source)
			}
			destinationMatches := sameUDPAddr(clientUDP, source)
			clientMu.Unlock()
			if !destinationMatches {
				continue
			}
			if err := p.forwardSOCKS5UDPDatagram(relayCtx, buffer[:count]); err != nil {
				if errors.Is(err, errSOCKS5UDPPacket) {
					continue
				}
				errorsCh <- err
				return
			}
		}
	}()

	go func() {
		var buffer [256]byte
		for {
			if _, err := control.Read(buffer[:]); err != nil {
				if relayCtx.Err() == nil {
					errorsCh <- nil
				}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsCh:
		cancel()
		_ = udpConn.Close()
		if err != nil && !errors.Is(err, errProxyNotReady) {
			p.markFailed(fmt.Errorf("UDP association failed: %w", err))
		}
		return err
	}
}

func writeSOCKS5Reply(writer io.Writer, code byte, address net.Addr) error {
	host := "0.0.0.0"
	port := 0
	if address != nil {
		parsedHost, parsedPort, err := net.SplitHostPort(address.String())
		if err != nil {
			return fmt.Errorf("parse SOCKS5 bind address: %w", err)
		}
		host = parsedHost
		parsed, err := strconv.Atoi(parsedPort)
		if err != nil || parsed < 0 || parsed > 65535 {
			return fmt.Errorf("invalid SOCKS5 bind port %q", parsedPort)
		}
		port = parsed
	}
	reply := []byte{socks5Version, code, 0}
	reply, err := appendSOCKS5Address(reply, host, uint16(port))
	if err != nil {
		return err
	}
	return writeFull(writer, reply)
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func isSupportedSOCKSAddressType(atyp byte) bool {
	return atyp == socksATYPIPv4 || atyp == socksATYPDomain || atyp == socksATYPIPv6
}
func readSOCKS5AddressBody(reader io.Reader, atyp byte) (string, uint16, error) {
	switch atyp {
	case socksATYPIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 IPv4 address: %w", err)
		}
		port, err := readSOCKS5Port(reader)
		return net.IP(raw[:]).String(), port, err
	case socksATYPIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 IPv6 address: %w", err)
		}
		port, err := readSOCKS5Port(reader)
		return net.IP(raw[:]).String(), port, err
	case socksATYPDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 domain length: %w", err)
		}
		if length[0] == 0 || int(length[0]) > maxSOCKS5DomainLength {
			return "", 0, errSOCKSProtocol
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 domain: %w", err)
		}
		host := string(raw)
		if err := validateDomain(host); err != nil {
			return "", 0, err
		}
		port, err := readSOCKS5Port(reader)
		return host, port, err
	default:
		return "", 0, errSocksAddressType
	}
}

// readSOCKS5Port permits port zero because UDP ASSOCIATE requests commonly use
// 0.0.0.0:0. CONNECT validates the resulting target and rejects zero there.
func readSOCKS5Port(reader io.Reader) (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return 0, fmt.Errorf("read SOCKS5 port: %w", err)
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

func parseSOCKS5UDPPacket(packet []byte) (egress.OpenTarget, []byte, error) {
	if len(packet) < 4 {
		return egress.OpenTarget{}, nil, errSOCKSProtocol
	}
	if packet[0] != 0 || packet[1] != 0 {
		return egress.OpenTarget{}, nil, errSOCKSProtocol
	}
	if packet[2] != 0 {
		return egress.OpenTarget{}, nil, errors.New("SOCKS5 UDP fragmentation is not supported")
	}
	host, port, consumed, err := parseSOCKS5AddressBody(packet[3:], packet[3])
	if err != nil {
		return egress.OpenTarget{}, nil, err
	}
	if len(packet) <= 3+consumed {
		return egress.OpenTarget{}, nil, errors.New("SOCKS5 UDP payload is empty")
	}
	payload := append([]byte(nil), packet[3+consumed:]...)
	target := egress.OpenTarget{Host: host, Port: port, Protocol: egress.ProtocolUDP}
	if err := target.Validate(); err != nil {
		return egress.OpenTarget{}, nil, err
	}
	return target, payload, nil
}

func parseSOCKS5AddressBody(packet []byte, atyp byte) (string, uint16, int, error) {
	switch atyp {
	case socksATYPIPv4:
		if len(packet) < 7 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		port := binary.BigEndian.Uint16(packet[5:7])
		if port == 0 {
			return "", 0, 0, errSOCKSProtocol
		}
		return net.IP(packet[1:5]).String(), port, 7, nil
	case socksATYPIPv6:
		if len(packet) < 19 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		port := binary.BigEndian.Uint16(packet[17:19])
		if port == 0 {
			return "", 0, 0, errSOCKSProtocol
		}
		return net.IP(packet[1:17]).String(), port, 19, nil
	case socksATYPDomain:
		if len(packet) < 2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		length := int(packet[1])
		if length == 0 {
			return "", 0, 0, errSOCKSProtocol
		}
		next := 2 + length + 2
		if len(packet) < next {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		host := string(packet[2 : 2+length])
		if err := validateDomain(host); err != nil {
			return "", 0, 0, err
		}
		port := binary.BigEndian.Uint16(packet[2+length : next])
		if port == 0 {
			return "", 0, 0, errSOCKSProtocol
		}
		return host, port, next, nil
	default:
		return "", 0, 0, errSocksAddressType
	}
}

func encodeSOCKS5UDPPacket(host string, port uint16, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("SOCKS5 UDP response payload is empty")
	}
	packet := []byte{0, 0, 0}
	packet, err := appendSOCKS5Address(packet, host, port)
	if err != nil {
		return nil, err
	}
	if len(packet)+len(payload) > maxSOCKS5UDPPacketSize {
		return nil, errors.New("SOCKS5 UDP packet exceeds 65535 bytes")
	}
	return append(packet, payload...), nil
}

func appendSOCKS5Address(destination []byte, host string, port uint16) ([]byte, error) {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		if err := validateDomain(host); err != nil {
			return nil, err
		}
		destination = append(destination, socksATYPDomain, byte(len(host)))
		destination = append(destination, host...)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		destination = append(destination, socksATYPIPv4)
		destination = append(destination, ipv4...)
	} else {
		ipv6 := ip.To16()
		if ipv6 == nil {
			return nil, errSocksAddressType
		}
		destination = append(destination, socksATYPIPv6)
		destination = append(destination, ipv6...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	destination = append(destination, portBytes[:]...)
	return destination, nil
}

func validateDomain(host string) error {
	if host == "" || len(host) > maxSOCKS5DomainLength {
		return fmt.Errorf("invalid SOCKS5 domain length %d", len(host))
	}
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "\x00\r\n\t /") {
		return errors.New("invalid SOCKS5 domain")
	}
	return nil
}

func validateLoopbackListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not a literal loopback IP", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return fmt.Errorf("invalid listen port %q", port)
	}
	return nil
}

func loopbackIPFromAddress(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil
	}
	return ip
}

func isLoopbackAddr(address net.Addr) bool {
	ip := addressIP(address)
	return ip != nil && ip.IsLoopback()
}

func addressIP(address net.Addr) net.IP {
	if address == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	return net.ParseIP(host)
}

func cloneAddr(address net.Addr) net.Addr {
	if udpAddress, ok := address.(*net.UDPAddr); ok {
		copy := *udpAddress
		copy.IP = append(net.IP(nil), udpAddress.IP...)
		return &copy
	}
	return address
}

func sameUDPAddr(left, right net.Addr) bool {
	leftUDP, leftOK := left.(*net.UDPAddr)
	rightUDP, rightOK := right.(*net.UDPAddr)
	if !leftOK || !rightOK {
		return left != nil && right != nil && left.String() == right.String()
	}
	return leftUDP.Port == rightUDP.Port && leftUDP.IP.Equal(rightUDP.IP)
}
