package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/magicsock"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

func testEngine(t *testing.T, c Config) *Engine {
	t.Helper()
	c.StaticNetwork = true
	if c.PrivateKey.scalar.IsZero() {
		c.PrivateKey = NodePrivateFromBytes(key.NewNode().Raw32())
	}
	e, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func pair(t *testing.T, a, b *Engine) {
	t.Helper()
	for _, p := range [][2]*Engine{{a, b}, {b, a}} {
		if err := p[0].SetPeers([]Peer{{NodeKey: p[1].PublicKey(), DiscoKey: p[1].DiscoKey(), Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p[1].LocalPort())}, Expires: time.Now().Add(30 * time.Second)}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for _, p := range [][2]*Engine{{a, b}, {b, a}} {
		poll(t, ctx, func() bool {
			_, _ = p[0].ping(ctx, nodePublic(p[1].PublicKey()))
			return p[0].Path(p[1].PublicKey()).Class == "direct"
		})
	}
}

func poll(t *testing.T, ctx context.Context, predicate func() bool) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !predicate() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}

func engines(t *testing.T) (*Engine, *Engine, *tls.Config) {
	t.Helper()
	a := testEngine(t, Config{})
	b := testEngine(t, Config{})
	pair(t, a, b)
	return a, b, testTLS(t)
}

func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}

func TestEngineStartExposesDFBind(t *testing.T) {
	e := testEngine(t, Config{})
	if e.PacketConn() == nil || !e.packets.SupportsDF() {
		t.Fatal("engine does not expose DF-capable bind")
	}
}

// This assertion is separate from the scalar test so the Mac's Key filter
// remains free of sockets.
func TestEngineStartsClampedPrivate(t *testing.T) {
	k := NodePrivateFromBytes([32]byte{0: 255, 31: 255})
	e := testEngine(t, Config{PrivateKey: k})
	if e.PublicKey() != k.Public() {
		t.Fatal("engine did not use the clamped key")
	}
}

func TestFixedPortRefusesFallback(t *testing.T) {
	busy, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(busy.LocalAddr().(*net.UDPAddr).Port)
	e, err := New(t.Context(), Config{PrivateKey: NodePrivateFromBytes(key.NewNode().Raw32()), Port: port, StaticNetwork: true})
	if e != nil {
		_ = e.Close()
	}
	if !errors.Is(err, ErrPortUnavailable) {
		t.Fatalf("New error=%v, want ErrPortUnavailable", err)
	}
	if err := busy.Close(); err != nil {
		t.Fatal(err)
	}
	bound := testEngine(t, Config{Port: port})
	if bound.LocalPort() != port {
		t.Fatalf("port=%d, want %d", bound.LocalPort(), port)
	}
}

func TestNetnsBindingOff(t *testing.T) {
	e := testEngine(t, Config{})
	if netns.Listener(logger.Discard, e.monitor).Control != nil {
		t.Fatal("network namespace binding remains enabled")
	}
}

func TestPeerDiscoveryStateSurvivesSetPeers(t *testing.T) {
	a, b, _ := engines(t)
	k := nodePublic(b.PublicKey())
	a.packets.mu.Lock()
	handle := a.packets.peers[k]
	a.packets.mu.Unlock()
	first := a.peer(k)
	for i := range 3 {
		endpoints := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.LocalPort()), netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:41641", i+1))}
		if err := a.SetPeers([]Peer{{NodeKey: b.PublicKey(), DiscoKey: b.DiscoKey(), Endpoints: endpoints, Expires: time.Now().Add(time.Minute)}}); err != nil {
			t.Fatal(err)
		}
		a.packets.mu.Lock()
		current := a.packets.peers[k]
		a.packets.mu.Unlock()
		if current != handle || a.peer(k).ID() != first.ID() {
			t.Fatal("endpoint update replaced magicsock discovery state")
		}
	}
}

func TestBindReceiveFunctionOrder(t *testing.T) {
	netns.SetEnabled(false)
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	monitor := netmon.NewStatic()
	t.Cleanup(func() { _ = monitor.Close() })
	metrics := new(usermetric.Registry)
	h := health.NewTracker(bus)
	h.SetMetricsRegistry(metrics)
	magic, err := magicsock.NewConn(magicsock.Options{
		EventBus:          bus,
		NetMon:            monitor,
		HealthTracker:     h,
		Metrics:           metrics,
		Logf:              logger.Discard,
		DisablePortMapper: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := magic.Close(); err != nil {
			t.Error(err)
		}
	})
	magic.SetPreferredPort(magic.LocalPort())
	if err := magic.SetPrivateKey(key.NewNode()); err != nil {
		t.Fatal(err)
	}
	fns, _, err := magic.Bind().Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = magic.Bind().Close() }()
	if len(fns) != 3 {
		t.Fatalf("receive functions=%d, want 3", len(fns))
	}
	for i, network := range []string{"udp4", "udp6"} {
		address := net.IPv4(127, 0, 0, 1)
		if i == 1 {
			address = net.IPv6loopback
		}
		c, err := net.DialUDP(network, nil, &net.UDPAddr{IP: address, Port: int(magic.LocalPort())})
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0xc0}, 1200)
		if _, err := c.Write(payload); err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		_ = c.Close()
		timer := time.AfterFunc(time.Second, func() { _ = magic.Bind().Close() })
		slab := make([]byte, 2*(1<<16-1))
		packets := make([]conn.ReceivedPacket, magic.Bind().BatchSize())
		n, err := fns[i](slab, packets)
		timer.Stop()
		if err != nil || n != 1 || !bytes.Equal(packets[0].Bytes(slab), payload) {
			t.Fatalf("receive index %d (%s): n=%d err=%v", i, network, n, err)
		}
	}
	if name := runtime.FuncForPC(reflect.ValueOf(fns[2]).Pointer()).Name(); !strings.Contains(name, "receiveDERP") {
		t.Fatalf("receive index 2=%s, want receiveDERP", name)
	}
}

func signalingFixture(t *testing.T) (*derpserver.Server, func(context.Context, string) (net.Conn, error)) {
	t.Helper()
	s := derpserver.New(key.NewNode(), t.Logf)
	t.Cleanup(func() { _ = s.Close() })
	return s, func(ctx context.Context, _ string) (net.Conn, error) {
		// DERP writes server info and the preferred-region frame concurrently.
		client, server := memnet.NewConn("signaling", 256<<10)
		go s.Accept(t.Context(), server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), "127.0.0.1:1")
		return client, nil
	}
}

func TestSignalingRegionSynthesized(t *testing.T) {
	srv, dial := signalingFixture(t)
	urls := make(chan string, 32)
	a := testEngine(t, Config{Signaling: &Signaling{RegionID: 0, Dial: func(ctx context.Context, url string) (net.Conn, error) { urls <- url; return dial(ctx, url) }}})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case url := <-urls:
		if url != "" {
			t.Fatalf("synthesized URL=%q, want empty", url)
		}
	case <-ctx.Done():
		t.Fatal("synthesized region did not dial without a peer")
	}
	b := testEngine(t, Config{Signaling: &Signaling{RegionID: 0, Dial: dial}})
	for _, p := range [][2]*Engine{{a, b}, {b, a}} {
		if err := p[0].SetPeers([]Peer{{NodeKey: p[1].PublicKey(), DiscoKey: p[1].DiscoKey(), HomeRegion: 0, Expires: time.Now().Add(time.Minute)}}); err != nil {
			t.Fatal(err)
		}
	}
	// The signaling server drops a packet for a peer that has not registered,
	// and a disco ping is sent once. Ping only after both engines are present.
	poll(t, ctx, func() bool {
		return srv.IsClientConnectedForTest(nodePublic(a.PublicKey())) && srv.IsClientConnectedForTest(nodePublic(b.PublicKey()))
	})
	if pong, err := a.ping(ctx, nodePublic(b.PublicKey())); err != nil || pong.DERPRegionID == 0 {
		t.Fatalf("region-zero disco pong=%+v err=%v", pong, err)
	}
	listed := "https://listed.invalid/signal"
	if err := a.SetRegions([]protocol.Region{{ID: 0, Code: "listed", URL: listed}}); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case url := <-urls:
			if url == listed {
				return
			}
		case <-ctx.Done():
			t.Fatal("listed region did not replace synthesized region")
		}
	}
}

func TestRelayedDataGatePerPeer(t *testing.T) {
	srv, dial := signalingFixture(t)
	allowedKey := NodePrivateFromBytes(key.NewNode().Raw32())
	deniedKey := NodePrivateFromBytes(key.NewNode().Raw32())
	a := testEngine(t, Config{Signaling: &Signaling{Dial: dial}, RelayedDataAllowed: func(k protocol.NodeKey) bool { return k == allowedKey.Public() }})
	allowed := testEngine(t, Config{PrivateKey: allowedKey, Signaling: &Signaling{Dial: dial}, RelayedDataAllowed: func(protocol.NodeKey) bool { return true }})
	denied := testEngine(t, Config{PrivateKey: deniedKey, Signaling: &Signaling{Dial: dial}, RelayedDataAllowed: func(protocol.NodeKey) bool { return true }})
	for _, e := range []*Engine{a, allowed, denied} {
		var ps []Peer
		for _, other := range []*Engine{a, allowed, denied} {
			if other != e {
				ps = append(ps, Peer{NodeKey: other.PublicKey(), DiscoKey: other.DiscoKey(), HomeRegion: 0, Expires: time.Now().Add(time.Minute)})
			}
		}
		if err := e.SetPeers(ps); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// The signaling server drops a packet for a peer that has not registered,
	// and each disco ping below is sent once. Ping only after all three engines
	// are present.
	poll(t, ctx, func() bool {
		for _, e := range []*Engine{a, allowed, denied} {
			if !srv.IsClientConnectedForTest(nodePublic(e.PublicKey())) {
				return false
			}
		}
		return true
	})
	for _, peer := range []*Engine{allowed, denied} {
		if pong, err := a.ping(ctx, nodePublic(peer.PublicKey())); err != nil || pong.DERPRegionID == 0 {
			t.Fatalf("relay disco=%+v err=%v", pong, err)
		}
	}
	for _, peer := range []*Engine{allowed, denied} {
		if _, err := a.PacketConn().WriteTo(make([]byte, 1200), Addr{Key: peer.PublicKey()}); err != nil {
			t.Fatal(err)
		}
	}
	_ = allowed.PacketConn().SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := allowed.PacketConn().ReadFrom(make([]byte, 1452)); err != nil || n != 1200 {
		t.Fatalf("allowed receive=%d err=%v", n, err)
	}
	// A disco reply fences the denied data send on the same ordered stream.
	if _, err := a.ping(ctx, nodePublic(denied.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if a.DERPDataSuppressed() != 1 {
		t.Fatalf("suppressed=%d, want 1", a.DERPDataSuppressed())
	}
	_ = denied.PacketConn().SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := denied.PacketConn().ReadFrom(make([]byte, 1452)); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("denied receive=%v, want deadline", err)
	}
	if _, err := denied.PacketConn().WriteTo(make([]byte, 1200), Addr{Key: a.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	poll(t, ctx, func() bool { return a.Counters().DERPDrops == 1 })
	if a.Counters().ReceiveBatches != 0 {
		t.Fatal("denied inbound DERP data was admitted")
	}
	// Both peers' disco still works after data suppression.
	for _, peer := range []*Engine{allowed, denied} {
		if _, err := a.ping(ctx, nodePublic(peer.PublicKey())); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebSocketDialerSendsHeadersEveryConnect(t *testing.T) {
	s := derpserver.New(key.NewNode(), t.Logf)
	defer func() { _ = s.Close() }()
	requests := make(chan http.Header, 4)
	var handlers sync.WaitGroup
	hs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		requests <- r.Header.Clone()
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"derp"}})
		if err != nil {
			t.Error(err)
			return
		}
		stream := wsconn.NetConn(t.Context(), c, websocket.MessageBinary, r.URL.String())
		s.Accept(t.Context(), stream, bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream)), "127.0.0.1:1")
	}))
	defer hs.Close()
	defer handlers.Wait()
	digest := sha256.Sum256(hs.Certificate().RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(digest[:])
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		actual := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if base64.StdEncoding.EncodeToString(actual[:]) != pin {
			return errors.New("SPKI mismatch")
		}
		return nil
	}}
	calls := 0
	dial := WebSocketDialer(tlsConfig, func(context.Context) (http.Header, error) {
		calls++
		return http.Header{"X-Session": {fmt.Sprintf("credential-%d", calls)}, "X-Device": {"device"}}, nil
	})
	mon := netmon.NewStatic()
	defer func() { _ = mon.Close() }()
	for i := 1; i <= 2; i++ {
		client, err := derphttp.NewClient(key.NewNode(), hs.URL+"/signal", t.Logf, mon)
		if err != nil {
			t.Fatal(err)
		}
		client.StreamDial = dial
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		err = client.Connect(ctx)
		cancel()
		if err != nil {
			_ = client.Close()
			t.Fatal(err)
		}
		h := <-requests
		if h.Get("X-Session") != fmt.Sprintf("credential-%d", i) || h.Get("X-Device") != "device" {
			t.Fatalf("connect %d headers=%v", i, h)
		}
		for name := range h {
			switch name {
			case "X-Session", "X-Device", "Connection", "Upgrade", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Protocol", "Sec-Websocket-Extensions", "User-Agent", "Accept-Encoding":
			default:
				t.Fatalf("unexpected header %q", name)
			}
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("headers called %d times, want 2", calls)
	}
	if _, err := dial(t.Context(), "http://region.invalid/signal"); err == nil {
		t.Fatal("HTTP signaling accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dial(ctx, hs.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial=%v", err)
	}
}

// Retain a concrete disco message reference in the relay fixture's package.
var _ disco.Message = (*disco.Ping)(nil)
var _ *quic.Conn

// A removed peer's client must receive the application close, not wait for its
// idle timeout.
func TestRemovedPeerClientSeesLeaseRemoved(t *testing.T) {
	server, client, tlsConf := engines(t)
	srvTransport := &quic.Transport{Conn: server.PacketConn()}
	t.Cleanup(func() { _ = srvTransport.Close() })
	srvTLS := tlsConf.Clone()
	srvTLS.NextProtos = []string{"test"}
	l, err := srvTransport.Listen(srvTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	cliTransport := &quic.Transport{Conn: client.PacketConn()}
	t.Cleanup(func() { _ = cliTransport.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := cliTransport.Dial(ctx, Addr{Key: server.PublicKey()}, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"test"}}, &quic.Config{MaxIdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.TrackConnection(accepted); err != nil {
		t.Fatal(err)
	}
	if err := server.SetPeers(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("client saw no close within 5 s of the peer's removal")
	}
	var appErr *quic.ApplicationError
	if !errors.As(context.Cause(conn.Context()), &appErr) || !appErr.Remote || appErr.ErrorCode != 0x100 || appErr.ErrorMessage != "lease removed" {
		t.Fatalf("client close = %v, want remote application error 0x100 \"lease removed\"", context.Cause(conn.Context()))
	}
}
