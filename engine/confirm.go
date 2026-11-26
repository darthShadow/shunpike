package engine

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

const (
	probeConcurrency     = 32
	confirmationLifetime = time.Second
)

func (e *Engine) probePeers(ctx context.Context, keys []key.NodePublic) {
	jobs := make(chan key.NodePublic)
	var workers sync.WaitGroup
	for range min(probeConcurrency, len(keys)) {
		workers.Go(func() {
			for k := range jobs {
				if ctx.Err() != nil {
					return
				}
				pingCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
				_, _ = e.ping(pingCtx, k)
				stop()
			}
		})
	}
feed:
	for _, k := range keys {
		select {
		case jobs <- k:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	workers.Wait()
}

func (e *Engine) confirmedPongLocked(k key.NodePublic) (protocol.Confirmation, bool) {
	c, ok := e.pongs[k]
	p, present := e.peerConfig[k]
	now := time.Now()
	if ok && (e.closed || !present || !now.Before(p.Expires) || !now.Before(e.discovery[k].lastPong.Add(confirmationLifetime)) || !e.windowOpen()) {
		delete(e.pongs, k)
		e.notifyRegistration()
		return protocol.Confirmation{}, false
	}
	return c, ok
}

func (e *Engine) ping(ctx context.Context, k key.NodePublic) (*ipnstate.PingResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.windowOpen() {
		return nil, errWindowEnded
	}
	e.mu.RLock()
	n := e.peers[k]
	p := e.peerConfig[k]
	valid := !e.closed && time.Now().Before(p.Expires)
	e.mu.RUnlock()
	if !n.Valid() || !valid {
		return nil, fmt.Errorf("no peer lease")
	}
	ch := make(chan *ipnstate.PingResult, 1)
	e.disco.Ping(n, new(ipnstate.PingResult), 0, func(r *ipnstate.PingResult) {
		e.recordPong(k, n.DiscoKey(), r)
		select {
		case ch <- r:
		default:
		}
	})
	select {
	case r := <-ch:
		if r == nil {
			return nil, fmt.Errorf("empty disco reply")
		}
		if r.Err != "" {
			return r, fmt.Errorf("disco: %s", r.Err)
		}
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Engine) recordPong(k key.NodePublic, disco key.DiscoPublic, pong *ipnstate.PingResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.peers[k]
	now := time.Now()
	if !n.Valid() || n.DiscoKey() != disco || e.closed || !now.Before(e.peerConfig[k].Expires) || !e.windowOpen() {
		return
	}
	old, had := e.confirmedPongLocked(k)
	if directPong(pong) {
		endpoint, _ := netip.ParseAddrPort(pong.Endpoint)
		c := protocol.Confirmation{Peer: nodeKey(k), DiscoKey: discoKey(disco), Endpoint: endpoint}
		e.pongs[k] = c
		d := e.discovery[k]
		d.lastPong = now
		// Stamp at receipt of the direct pong, independently of Path readers.
		if d.direct.IsZero() && !d.first.IsZero() {
			d.direct = now
		}
		e.discovery[k] = d
		if !had || old != c {
			e.notifyRegistration()
		}
	} else if pong != nil && had {
		delete(e.pongs, k)
		e.notifyRegistration()
	}
	signal(e.leaseChanged)
}

func (e *Engine) notifyRegistration() { signal(e.endpointChanged) }
