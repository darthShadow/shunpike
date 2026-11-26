package engine_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
	"github.com/darthShadow/shunpike/internal/testcoord"
)

func TestClientDefaultSignalRegion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		listed bool
	}{{"default", false}, {"listed", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			l := newLab(t, ctx, tc.listed)
			h := l.startHost(t, engine.NodePrivateFromBytes(key.NewNode().Raw32()))
			d := l.newDevice(t, "phone")
			l.ready(t, d, h)
			want, other := l.ts.URL+"/signal", l.ts.URL+"/signal?via=listed"
			if tc.listed {
				want, other = other, want
			}
			waitFor(t, "signaling dial of "+want, 5*time.Second, func() bool { return slices.Contains(d.dialed(), want) })
			waitFor(t, "region accepting the signaling connection", 5*time.Second, func() bool { return l.count(http.MethodGet, "/signal") > 0 })
			if dialed := d.dialed(); slices.Contains(dialed, other) {
				t.Fatalf("engine dialed %q, which the netmap did not name; dialed %q", other, dialed)
			}
		})
	}
}

func TestClientRegistrationNotChurned(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	l := newLab(t, ctx, false)
	h := l.startHost(t, engine.NodePrivateFromBytes(key.NewNode().Raw32()))
	d := l.newDevice(t, "phone")
	l.ready(t, d, h)
	// Let the registrations that follow discovery finish, then count a window
	// of steady direct pongs. The engine probes every 500 ms the whole time.
	time.Sleep(labRefresh + 500*time.Millisecond)
	const window = 5 * time.Second
	before := l.count(http.MethodPost, "/registration")
	time.Sleep(window)
	got := l.count(http.MethodPost, "/registration") - before
	if limit := 1 + int(window/labRefresh); got > limit {
		t.Fatalf("%d registrations in %v, want at most %d", got, window, limit)
	}
}

// freeUDPPort returns a loopback UDP port nothing holds at the moment.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// changePort moves the engine to a new UDP port and checks that it moved.
func changePort(t *testing.T, e *engine.Engine) {
	t.Helper()
	old := e.LocalPort()
	e.ChangePort(freeUDPPort(t))
	if e.LocalPort() == old {
		t.Fatalf("engine stayed on UDP port %d", old)
	}
}

func sameEndpoints(a, b []netip.AddrPort) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, func(x, y netip.AddrPort) int { return x.Compare(y) })
	slices.SortFunc(b, func(x, y netip.AddrPort) int { return x.Compare(y) })
	return slices.Equal(a, b)
}

// callMeMaybeBound is the time from a call-me-maybe send to its handling.
const callMeMaybeBound = 400 * time.Millisecond

// flowBetween sends a small packet each way every 20 ms until ctx ends and
// reads what arrives, so both engines count their peer's path as in use.
func flowBetween(ctx context.Context, a, b *engine.Engine) {
	for _, p := range [][2]*engine.Engine{{a, b}, {b, a}} {
		self, peer := p[0], p[1]
		go func() {
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			payload := make([]byte, 200)
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					_, _ = self.PacketConn().WriteTo(payload, engine.Addr{Key: peer.PublicKey()})
				}
			}
		}()
		go func() {
			buf := make([]byte, 1500)
			for ctx.Err() == nil {
				_ = self.PacketConn().SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, _, _ = self.PacketConn().ReadFrom(buf)
			}
		}()
	}
}

// callMeMaybeLag moves mover to a new UDP port and returns the time from the
// mover's call-me-maybe send to the other side's magicsock reading the message,
// which it handles at once in its own goroutine. The send is the first one
// after the mover announces its new endpoints. The send line is written once
// the send returns, so a quick read can be logged before it and counts as zero.
// The wait from the port change to the send is logged apart from the bound.
func callMeMaybeLag(t *testing.T, name string, mover *engine.Engine, sent, received *callMeMaybeLog) time.Duration {
	t.Helper()
	from := time.Now()
	changePort(t, mover)
	var announced, send, read time.Time
	waitFor(t, name+": announcement of the new endpoints", 10*time.Second, func() bool {
		at := sent.times(from, "announcing new endpoints")
		if len(at) == 0 {
			return false
		}
		announced = at[0]
		return true
	})
	waitFor(t, name+": send of a call-me-maybe", 5*time.Second, func() bool {
		at := sent.times(announced, "sent call-me-maybe")
		if len(at) == 0 {
			return false
		}
		send = at[0]
		return true
	})
	waitFor(t, name+": handling of the call-me-maybe", 5*time.Second, func() bool {
		at := received.times(announced, "got call-me-maybe")
		if len(at) == 0 {
			return false
		}
		read = at[0]
		return true
	})
	t.Logf("%s: send %v after the port change", name, send.Sub(from))
	return max(read.Sub(send), 0)
}

func TestEndToEndSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	l := newLab(t, ctx, false)
	hostKey := engine.NodePrivateFromBytes(key.NewNode().Raw32())

	// Step 1: enroll, register, netmap, signal connect, direct discovery.
	h := l.startHost(t, hostKey)
	priv, cred := l.newCredential(t, "phone")
	pongAt := make(chan time.Time, 1)
	go func() {
		for ctx.Err() == nil {
			if reg, err := h.e.Registration(); err == nil && slices.ContainsFunc(reg.Confirmations, func(c protocol.Confirmation) bool { return c.Peer == cred.node }) {
				pongAt <- time.Now()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	d := l.startDevice(t, priv, cred)
	l.ready(t, d, h)

	// Step 6: the host's confirmation reaches a netmap within 1 s of its pong.
	var pong time.Time
	select {
	case pong = <-pongAt:
	case <-ctx.Done():
		t.Fatal("host never confirmed the device:", ctx.Err())
	}
	delivered := time.Unix(0, l.firstConfirmation.Load())
	if delivered.Before(pong.Add(-50 * time.Millisecond)) {
		t.Fatalf("netmap carried the confirmation at %v, before the pong at %v", delivered, pong)
	}
	if lag := delivered.Sub(pong); lag > time.Second {
		t.Fatalf("confirmation reached the netmap %v after the pong, want within 1s", lag)
	}

	// Step 2: the device rebinds; the host sees its endpoints and the path recovers.
	changePort(t, d.e)
	waitFor(t, "host view of the device's new endpoints", 15*time.Second, func() bool {
		entry, ok := l.cur.Load().dir.Lookup(ctx, cred.node)
		reg, err := d.e.Registration()
		return ok && err == nil && sameEndpoints(entry.Endpoints, reg.Endpoints) &&
			slices.Contains(entry.Endpoints, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), d.e.LocalPort()))
	})
	l.ready(t, d, h)

	// Step 3: the host restarts with the same store; its new disco key reaches the netmap.
	oldDisco := h.e.DiscoKey()
	h.stop()
	h = l.startHost(t, hostKey)
	if h.e.DiscoKey() == oldDisco {
		t.Fatal("restarted host kept its disco key")
	}
	waitFor(t, "new host disco key in the netmap", 10*time.Second, func() bool {
		m, err := l.cur.Load().srv.Netmap(ctx, cred.principal(), "")
		return err == nil && len(m.Hosts) == 1 && m.Hosts[0].DiscoKey == h.e.DiscoKey()
	})
	l.ready(t, d, h)

	// Step 3 again: the server loses its store. The next request gets 401, the
	// device enrolls again, and the path recovers.
	refused := l.unauthorized()
	l.reset()
	h.stop()
	h = l.startHost(t, hostKey)
	waitFor(t, "401 and peer expiry", 15*time.Second, func() bool {
		return l.unauthorized() > refused && !d.e.IsPeer(h.e.PublicKey())
	})
	l.enroll(t, cred, time.Hour)
	l.ready(t, d, h)

	// Step 4: two lease rotations with renewed principals. The principal and
	// the lease each last 3 s and 4 s, and renew every 2 s.
	cred.setTTL(3 * time.Second)
	signals := l.count(http.MethodGet, "/signal")
	l.cur.Load().region.Disconnect(cred.node)
	for range 4 {
		l.enroll(t, cred, 4*time.Second)
		time.Sleep(2 * time.Second)
	}
	l.ready(t, d, h)
	if got := l.count(http.MethodGet, "/signal") - signals; got < 2 {
		t.Fatalf("%d signal connections over two rotations, want at least 2", got)
	}
	// Later steps need a device whose lease and principal outlast them. The
	// short principal ends its connection within 3 s; wait for the next one,
	// which carries the long principal.
	signals = l.count(http.MethodGet, "/signal")
	cred.setTTL(time.Hour)
	l.enroll(t, cred, time.Hour)
	waitFor(t, "a signal connection with the long principal", 10*time.Second, func() bool { return l.count(http.MethodGet, "/signal") > signals })
	l.ready(t, d, h)

	// Step 7: with media flowing and registration and netmap blocked, one side
	// changes its UDP port. Only a call-me-maybe through the region can carry
	// the change, and the other side handles it within 0.4 s of the send. The
	// path recovery that follows has the looser bound of the discovery cycle.
	l.block.Store(true)
	t.Cleanup(func() {
		if t.Failed() {
			d.cmm.dump(t, "device")
			h.cmm.dump(t, "host")
		}
	})
	flowCtx, stopFlow := context.WithCancel(ctx)
	defer stopFlow()
	flowBetween(flowCtx, d.e, h.e)
	for _, c := range []struct {
		name     string
		mover    *engine.Engine
		sent     *callMeMaybeLog
		received *callMeMaybeLog
	}{{"device to host", d.e, d.cmm, h.cmm}, {"host to device", h.e, h.cmm, d.cmm}} {
		lag := callMeMaybeLag(t, c.name, c.mover, c.sent, c.received)
		t.Logf("%s: call-me-maybe handled %v after the send", c.name, lag)
		if lag > callMeMaybeBound {
			t.Fatalf("%s: call-me-maybe handled %v after the send, want within %v", c.name, lag, callMeMaybeBound)
		}
		// Only the mover's sockets changed, so only a path to the mover has a port
		// to check. The path from the mover may use the other engine's IPv6
		// socket, whose port differs from LocalPort (the IPv4 socket's port) when
		// that engine started on port 0.
		other := h.e
		if c.mover == h.e {
			other = d.e
		}
		waitFor(t, c.name+": paths after the port change", 15*time.Second, func() bool {
			toMover, fromMover := other.Path(c.mover.PublicKey()), c.mover.Path(other.PublicKey())
			return toMover.Class == "direct" && toMover.Endpoint.Port() == c.mover.LocalPort() && fromMover.Class == "direct"
		})
	}
	stopFlow()
	l.block.Store(false)

	// Step 5: no request carried a header except the headers function's and
	// the ones the HTTP and WebSocket transports set.
	for _, r := range l.requests() {
		extra := []string{}
		for k := range r.header {
			switch {
			case k == testcoord.Header:
			case slices.Contains([]string{"User-Agent", "Accept-Encoding", "Content-Length", "Upgrade", "Connection"}, k):
			case strings.HasPrefix(k, "Sec-Websocket-"):
			default:
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 || r.header.Get(testcoord.Header) == "" {
			t.Fatalf("%s %s sent headers %v beyond the headers function's", r.method, r.path, extra)
		}
	}
}
