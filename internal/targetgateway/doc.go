// Package targetgateway provides a loopback-only TCP/UDP forwarding gateway for
// explicitly authorized Mesh targets.
//
// The gateway never creates a network interface, changes routes, resolves a
// hostname, or dials a target by itself. It accepts only a literal IPv4 target
// in the project's private Mesh ranges and delegates all data-plane work to an
// injected Dialer. Every new connection or UDP session, and every chunk or
// datagram forwarded afterwards, is checked against an injected LeaseValidator.
//
// The Dialer is a security boundary. It must bind the Mesh source address,
// constrain the route to the current Mesh interface, and refuse any fallback to
// a physical interface or the public Internet. A loopback listener is not an
// authentication boundary for other local processes.
package targetgateway
