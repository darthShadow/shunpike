package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go4.org/mem"
	_ "tailscale.com/feature/portmapper"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/magicsock"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// NodePrivate holds a clamped X25519 scalar. Its zero value is unconfigured.
type NodePrivate struct{ scalar key.NodePrivate }

// NodePrivateFromBytes accepts any bytes and clamps them as RFC 7748 specifies.
func NodePrivateFromBytes(b [32]byte) NodePrivate {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	scalar, err := key.ParseNodePrivateUntyped(mem.S(hex.EncodeToString(b[:])))
	if err != nil {
		panic(err)
	}
	return NodePrivate{scalar: scalar}
}

func (k NodePrivate) private() key.NodePrivate { return k.scalar }

// Public returns the public identity; an unconfigured private key returns zero.
func (k NodePrivate) Public() protocol.NodeKey {
	if k.scalar.IsZero() {
		return protocol.NodeKey{}
	}
	return nodeKey(k.private().Public())
}

func nodePublic(k protocol.NodeKey) key.NodePublic    { return key.NodePublicFromRaw32(mem.B(k[:])) }
func discoPublic(k protocol.DiscoKey) key.DiscoPublic { return key.DiscoPublicFromRaw32(mem.B(k[:])) }

// Signaling supplies the only connection path to the engine's home region.
// Dial receives an empty URL until a listed region supplies one.
type Signaling struct {
	RegionID int
	Dial     func(ctx context.Context, url string) (net.Conn, error)
}

// Config controls one engine. A zero Port requests an ephemeral UDP port.
// Nil RelayedDataAllowed denies all relayed data. StaticNetwork disables mapping.
type Config struct {
	PrivateKey         NodePrivate
	Port               uint16
	Logger             *slog.Logger
	Signaling          *Signaling
	Regions            []protocol.Region
	STUNServers        []string
	PortMapping        bool
	GSO                bool
	RelayedDataAllowed func(peer protocol.NodeKey) bool
	StaticNetwork      bool
	// Window, when set, returns the instant the engine's permission to exchange
	// packets with peers ends; a zero or past instant means it has ended. The
	// engine reads it before each probe, on each pong, confirmation read, peer
	// update and lease check, and again at the instant it returned, so a later
	// instant extends the permission. Once it has ended the engine removes every
	// peer, so magicsock sends and accepts no discovery for them, and it records
	// no confirmation and installs no later peer until Close. Until the expiry
	// loop has removed the peers, magicsock can still answer a ping already in
	// flight: one timer firing and one peer update, or up to one 500 ms probe
	// round when Window ends without moving its instant. The engine may call
	// Window while it holds its own locks, so Window must not call the engine.
	// Nil sets no limit.
	Window func() time.Time
}

// Validate refuses an unconfigured key, missing dialer and malformed servers or regions.
func (c Config) Validate() error {
	if c.PrivateKey.scalar.IsZero() {
		return errors.New("node private key required")
	}
	if c.Signaling != nil && (c.Signaling.Dial == nil || c.Signaling.RegionID < 0) {
		return errors.New("signaling requires a nonnegative region and dialer")
	}
	if len(c.STUNServers) > 0 {
		if _, err := stunMap(c.STUNServers); err != nil {
			return err
		}
	}
	return validateRegions(c.Regions)
}

type discoConn interface {
	Ping(tailcfg.NodeView, *ipnstate.PingResult, int, func(*ipnstate.PingResult))
	DiscoPublicKey() key.DiscoPublic
	UpdateStatus(*ipnstate.StatusBuilder)
}
type directDiscovery struct{ first, direct, lastPong time.Time }

// Engine owns one magicsock bind and its shared packet adapter. Close releases both.
type Engine struct {
	config          Config
	private         NodePrivate
	magic           *magicsock.Conn
	disco           discoConn
	packets         *packetConn
	bus             *eventbus.Bus
	health          *health.Tracker
	monitor         *netmon.Monitor
	unregister      func()
	ctx             context.Context
	cancel          context.CancelFunc
	workers         sync.WaitGroup
	mu              sync.RWMutex
	applyMu         sync.Mutex
	peers           map[key.NodePublic]tailcfg.NodeView
	peerConfig      map[key.NodePublic]Peer
	pongs           map[key.NodePublic]protocol.Confirmation
	discovery       map[key.NodePublic]directDiscovery
	connections     map[*quic.Conn]key.NodePublic
	regions         []protocol.Region
	regionIDs       map[int]tailcfg.DERPRegionID
	endpointChanged chan struct{}
	probeChanged    chan struct{}
	leaseChanged    chan struct{}
	endpoints       []tailcfg.Endpoint
	lastPort        uint16
	portDriftLogged bool
	timerWake       func() // observes deadline firings in clock-controlled tests
	windowEnded     atomic.Bool
	once            sync.Once
	closed          bool
	closeErr        error
}

// New validates c and opens ordinary UDP sockets. It returns ErrPortUnavailable
// if the configured fixed port is unavailable, releasing all partial resources.
func New(ctx context.Context, c Config) (_ *Engine, retErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	netns.SetEnabled(false)
	ctx, cancel := context.WithCancel(ctx)
	c.Regions = append([]protocol.Region(nil), c.Regions...)
	c.STUNServers = append([]string(nil), c.STUNServers...)
	if c.Signaling != nil {
		s := *c.Signaling
		c.Signaling = &s
	}
	e := newEngineState(c)
	e.ctx, e.cancel, e.bus = ctx, cancel, eventbus.New()
	defer func() {
		if retErr != nil {
			_ = e.Close()
		}
	}()
	logf := probeLogf(ctx, c.Logger)
	e.health = health.NewTracker(e.bus)
	metrics := new(usermetric.Registry)
	e.health.SetMetricsRegistry(metrics)
	var err error
	if c.StaticNetwork {
		e.monitor = netmon.NewStatic()
	} else {
		e.monitor, err = netmon.New(e.bus, logf)
	}
	if err != nil {
		return nil, fmt.Errorf("network monitor: %w", err)
	}
	opts := magicsock.Options{Metrics: metrics, DisablePortMapper: !c.PortMapping || c.StaticNetwork, EventBus: e.bus, NetMon: e.monitor, HealthTracker: e.health, Logf: logf, Port: c.Port, EndpointsFunc: e.endpointsUpdated}
	e.configurePolicy(&opts)
	magic, err := magicsock.NewConn(opts)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.magic = magic
	e.mu.Unlock()
	e.disco = e.magic
	if err := e.checkPort(true); err != nil {
		return nil, err
	}
	fns, _, err := e.magic.Bind().Open(0)
	if err != nil {
		return nil, err
	}
	if len(fns) != 3 {
		return nil, fmt.Errorf("pinned magicsock receive order changed: %d functions", len(fns))
	}
	e.packets = newPacketConn(e.magic.Bind(), fns, e.relayedDataAllowed)
	e.packets.SetGSO(c.GSO)
	e.magic.SetNetworkUp(true)
	if err := e.magic.SetPrivateKey(c.PrivateKey.private()); err != nil {
		return nil, err
	}
	if err := e.SetRegions(c.Regions); err != nil {
		return nil, err
	}
	e.unregister = e.monitor.RegisterChangeCallback(func(d *netmon.ChangeDelta) {
		e.magic.SetNetworkUp(d.AnyInterfaceUp())
		if d.AnyInterfaceUp() {
			if d.RebindLikelyRequired {
				e.Rebind()
			}
			e.magic.ReSTUN("engine-link-change")
		}
	})
	e.monitor.Start()
	e.workers.Go(e.expiryLoop)
	e.workers.Go(func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-e.probeChanged:
			}
			e.mu.RLock()
			keys := make([]key.NodePublic, 0, len(e.peers))
			for k := range e.peers {
				keys = append(keys, k)
			}
			e.mu.RUnlock()
			e.probePeers(ctx, keys)
		}
	})
	return e, nil
}

// PublicKey returns this engine's stable node identity.
func (e *Engine) PublicKey() protocol.NodeKey { return e.private.Public() }

// DiscoKey returns the current discovery identity.
func (e *Engine) DiscoKey() protocol.DiscoKey {
	return discoKey(e.disco.DiscoPublicKey())
}

// LocalPort returns the actual bound UDP port.
func (e *Engine) LocalPort() uint16 { return e.magic.LocalPort() }

// Changed returns a capacity-1 coalescing channel for one registration reader.
func (e *Engine) Changed() <-chan struct{} { return e.endpointChanged }

// PacketConn returns the shared packet adapter. Its lifetime ends with Close.
func (e *Engine) PacketConn() net.PacketConn { return e.packets }

// Counters returns cumulative adapter statistics without resetting them.
func (e *Engine) Counters() Counters { return e.packets.Counters() }

// DERPDataSuppressed returns the number of relayed sends denied by policy.
func (e *Engine) DERPDataSuppressed() int64 { return e.magic.DERPDataSuppressed() }

// Close cancels work and releases connections, sockets and monitors exactly once.
// It returns any socket or monitor close error; repeated calls return that error.
func (e *Engine) Close() error {
	e.once.Do(func() {
		e.cancel()
		if e.unregister != nil {
			e.unregister()
		}
		e.workers.Wait()
		e.applyMu.Lock()
		e.mu.Lock()
		e.closed = true
		conns := e.connections
		e.connections = map[*quic.Conn]key.NodePublic{}
		e.mu.Unlock()
		for c := range conns {
			_ = c.CloseWithError(0x100, "engine closed")
		}
		if e.packets != nil {
			e.closeErr = errors.Join(e.closeErr, e.packets.Close())
		}
		if e.magic != nil {
			e.closeErr = errors.Join(e.closeErr, e.magic.Close())
		}
		e.applyMu.Unlock()
		if e.monitor != nil {
			e.closeErr = errors.Join(e.closeErr, e.monitor.Close())
		}
		if e.bus != nil {
			e.bus.Close()
		}
	})
	return e.closeErr
}

func nodeKey(k key.NodePublic) protocol.NodeKey {
	var b [32]byte
	k.AppendTo(b[:0])
	return protocol.NodeKey(b)
}
func discoKey(k key.DiscoPublic) protocol.DiscoKey {
	var b [32]byte
	k.AppendTo(b[:0])
	return protocol.DiscoKey(b)
}

// newEngineState initializes the same peer state and notification channels for
// socket startup and clock-controlled discovery tests. It opens no resources.
func newEngineState(c Config) *Engine {
	return &Engine{config: c, private: c.PrivateKey,
		peers: map[key.NodePublic]tailcfg.NodeView{}, peerConfig: map[key.NodePublic]Peer{}, pongs: map[key.NodePublic]protocol.Confirmation{}, discovery: map[key.NodePublic]directDiscovery{}, connections: map[*quic.Conn]key.NodePublic{}, regionIDs: map[int]tailcfg.DERPRegionID{}, endpointChanged: make(chan struct{}, 1), probeChanged: make(chan struct{}, 1), leaseChanged: make(chan struct{}, 1)}
}
