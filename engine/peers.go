package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// Peer is a leased node identity and its independent confirmation of this engine.
type Peer struct {
	NodeKey      protocol.NodeKey
	DiscoKey     protocol.DiscoKey
	Endpoints    []netip.AddrPort
	HomeRegion   int
	Expires      time.Time
	Confirmation *protocol.Confirmation
}

func validateRegions(rs []protocol.Region) error {
	seen := map[int]bool{}
	for _, r := range rs {
		if r.ID < 0 || seen[r.ID] {
			return errors.New("regions require unique nonnegative IDs")
		}
		seen[r.ID] = true
		if err := secureURL(r.URL); err != nil {
			return fmt.Errorf("region %d: %w", r.ID, err)
		}
	}
	return nil
}

// regionIDLocked reserves 1..len(STUNServers) for STUN. Protocol IDs use
// sequential IDs above that range, including protocol region zero.
func (e *Engine) regionIDLocked(id int) tailcfg.DERPRegionID {
	if internal, ok := e.regionIDs[id]; ok {
		return internal
	}
	internal := tailcfg.DERPRegionID(len(e.config.STUNServers) + len(e.regionIDs) + 1)
	e.regionIDs[id] = internal
	return internal
}

// SetRegions atomically replaces listed HTTPS signaling regions. A missing home
// region is synthesized for Signaling.Dial. Closed engines return net.ErrClosed.
func (e *Engine) SetRegions(rs []protocol.Region) error {
	if err := validateRegions(rs); err != nil {
		return err
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	dm := &tailcfg.DERPMap{OmitDefaultRegions: true, Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	if len(e.config.STUNServers) > 0 {
		var err error
		dm, err = stunMap(e.config.STUNServers)
		if err != nil {
			return err
		}
		dm.OmitDefaultRegions = true
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
	e.regions = slices.Clone(rs)
	all := slices.Clone(rs)
	if s := e.config.Signaling; s != nil {
		found := false
		for _, r := range all {
			if r.ID == s.RegionID {
				found = true
				break
			}
		}
		if !found {
			all = append(all, protocol.Region{ID: s.RegionID, Code: "signaling"})
		}
	}
	for _, r := range all {
		id := e.regionIDLocked(r.ID)
		host := "signaling.invalid"
		port := 443
		path := ""
		if r.URL != "" {
			u, _ := url.Parse(r.URL)
			host = u.Hostname()
			path = u.RequestURI()
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
		}
		n := &tailcfg.DERPNode{Name: strconv.Itoa(int(id)) + "a", RegionID: id, HostName: host, DERPPort: port, STUNPort: -1}
		// Include the full URL in the definition so a path-only replacement
		// also reconnects the region; the dial hook supplies the exact URL.
		dm.Regions[id] = &tailcfg.DERPRegion{RegionID: id, RegionCode: r.Code, RegionName: r.URL + path, Nodes: []*tailcfg.DERPNode{n}}
	}
	var home tailcfg.DERPRegionID
	if s := e.config.Signaling; s != nil {
		home = e.regionIDLocked(s.RegionID)
	}
	e.mu.Unlock()
	if e.magic != nil {
		e.magic.SetDERPMap(dm)
		if home != 0 {
			e.magic.ForceSetNearestDERP(home)
		}
	}
	return nil
}

func syntheticNode(k key.NodePublic) *tailcfg.Node {
	raw := nodeKey(k)
	sum := sha256.Sum256(raw[:])
	id := binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff
	if id == 0 {
		id = 1
	}
	var ip [16]byte
	copy(ip[:], sum[:16])
	ip[0] = 0xfd
	prefix := netip.PrefixFrom(netip.AddrFrom16(ip), 128)
	return &tailcfg.Node{ID: tailcfg.NodeID(id), Key: k, Name: k.UntypedHexString() + ".invalid.", Addresses: []netip.Prefix{prefix}, AllowedIPs: []netip.Prefix{prefix}}
}

// SetPeers replaces the graph. Keys and endpoints are copied; expired peers are
// removed. Discovery identity changes close that peer's tracked connections.
// Malformed or duplicate identities refuse the update before changing the graph.
func (e *Engine) SetPeers(ps []Peer) error {
	now := time.Now()
	next := make(map[key.NodePublic]Peer, len(ps))
	for _, p := range ps {
		if p.NodeKey.IsZero() || p.NodeKey == e.PublicKey() || p.DiscoKey.IsZero() || p.HomeRegion < 0 {
			return errors.New("peer requires a distinct node key, disco key and nonnegative home region")
		}
		k := nodePublic(p.NodeKey)
		if _, ok := next[k]; ok {
			return errors.New("duplicate peer")
		}
		for _, ep := range p.Endpoints {
			if !usableEndpoint(ep) {
				return errors.New("invalid peer endpoint")
			}
		}
		p.Endpoints = slices.Clone(p.Endpoints)
		slices.SortFunc(p.Endpoints, func(a, b netip.AddrPort) int { return a.Compare(b) })
		if p.Confirmation != nil {
			c := *p.Confirmation
			p.Confirmation = &c
		}
		if now.Before(p.Expires) {
			next[k] = p
		}
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	return e.applyPeersLocked(next, now)
}

func (e *Engine) applyPeersLocked(next map[key.NodePublic]Peer, now time.Time) error {
	// An ended packet window admits no peer, whatever the caller passes.
	if !e.windowOpen() {
		next = map[key.NodePublic]Peer{}
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
	old := e.peers
	peers := make(map[key.NodePublic]tailcfg.NodeView, len(next))
	views := make([]tailcfg.NodeView, 0, len(next))
	needsProbe := false
	changed := false
	for k, p := range next {
		n := syntheticNode(k)
		n.DiscoKey = discoPublic(p.DiscoKey)
		n.Endpoints = slices.Clone(p.Endpoints)
		n.KeyExpiry = p.Expires
		n.HomeDERP = e.regionIDLocked(p.HomeRegion)
		v := n.View()
		peers[k] = v
		views = append(views, v)
		prev, ok := old[k]
		if !ok || prev.DiscoKey() != v.DiscoKey() {
			e.discovery[k] = directDiscovery{first: now}
		}
		if !ok || prev.DiscoKey() != v.DiscoKey() || !slices.Equal(prev.Endpoints().AsSlice(), n.Endpoints) {
			if _, ok := e.pongs[k]; ok {
				changed = true
			}
			delete(e.pongs, k)
			needsProbe = true
		}
	}
	for k := range old {
		if _, ok := peers[k]; !ok {
			if _, ok := e.pongs[k]; ok {
				changed = true
			}
			delete(e.pongs, k)
			delete(e.discovery, k)
		}
	}
	e.peers = peers
	e.peerConfig = next
	e.mu.Unlock()
	if e.magic != nil {
		for k, n := range old {
			if v, ok := peers[k]; !ok {
				e.closePeer(k)
				e.magic.RemovePeer(n.ID())
			} else if v.DiscoKey() != n.DiscoKey() {
				e.closePeer(k)
			}
		}
		self := syntheticNode(e.private.private().Public())
		self.DiscoKey = e.disco.DiscoPublicKey()
		e.magic.SetNetworkMap(self.View(), views)
		handles := make(map[key.NodePublic]conn.Endpoint, len(peers))
		for k := range peers {
			ep, err := e.magic.ParseEndpoint(k.UntypedHexString())
			if err != nil {
				return err
			}
			handles[k] = ep
		}
		if e.packets != nil {
			e.packets.setPeers(handles)
		}
	} else {
		for k, n := range old {
			if v, ok := peers[k]; !ok || v.DiscoKey() != n.DiscoKey() {
				e.closePeer(k)
			}
		}
	}
	if changed {
		e.notifyRegistration()
	}
	if needsProbe {
		signal(e.probeChanged)
	}
	signal(e.leaseChanged)
	return nil
}

func (e *Engine) peer(k key.NodePublic) tailcfg.NodeView {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.peers[k]
}

// Expire removes every peer, its admission handles and tracked connections now.
func (e *Engine) Expire() {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	_ = e.applyPeersLocked(map[key.NodePublic]Peer{}, time.Now())
}

// IsPeer reports whether k has a live lease on this open engine.
func (e *Engine) IsPeer(k protocol.NodeKey) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.peerConfig[nodePublic(k)]
	return ok && !e.closed && time.Now().Before(p.Expires) && e.windowOpen()
}

func (e *Engine) expiryLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	timer.Stop()
	for {
		until, open := e.window()
		if !open {
			// The packet window has ended: with no peer in its map magicsock
			// sends and accepts no discovery, and later peer updates install none.
			e.Expire()
			<-e.ctx.Done()
			return
		}
		e.mu.RLock()
		var deadline time.Time
		for k, p := range e.peerConfig {
			if deadline.IsZero() || p.Expires.Before(deadline) {
				deadline = p.Expires
			}
			if _, ok := e.pongs[k]; ok {
				d := e.discovery[k].lastPong.Add(confirmationLifetime)
				if d.Before(deadline) {
					deadline = d
				}
			}
		}
		e.mu.RUnlock()
		if !until.IsZero() && (deadline.IsZero() || until.Before(deadline)) {
			deadline = until
		}
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer.Reset(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-e.ctx.Done():
			return
		case <-e.leaseChanged:
			timer.Stop()
			continue
		case <-timeout:
			if e.timerWake != nil {
				e.timerWake()
			}
		}
		e.applyMu.Lock()
		now := time.Now()
		e.mu.Lock()
		next := make(map[key.NodePublic]Peer, len(e.peerConfig))
		removed := false
		for k, p := range e.peerConfig {
			if now.Before(p.Expires) {
				next[k] = p
			} else {
				removed = true
			}
			e.confirmedPongLocked(k)
		}
		e.mu.Unlock()
		if removed {
			_ = e.applyPeersLocked(next, now)
		}
		e.applyMu.Unlock()
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
