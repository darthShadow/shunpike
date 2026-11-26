package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// windowAt is a Config.Window whose end instant a test moves.
type windowAt struct {
	mu  sync.Mutex
	end time.Time
}

func (w *windowAt) set(end time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.end = end
}

func (w *windowAt) until() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.end
}

// The expiry loop removes every peer at the window's end instant without
// polling, and an extension made before the instant keeps the peers until the
// new instant.
func TestWindowEndRemovesPeersAtItsInstant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(2)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.ctx = ctx
		w := &windowAt{end: time.Now().Add(200 * time.Millisecond)}
		e.config.Window = w.until
		var wakes atomic.Int64
		e.timerWake = func() { wakes.Add(1) }
		peers := func() int {
			e.mu.RLock()
			defer e.mu.RUnlock()
			return len(e.peers)
		}
		done := make(chan struct{})
		go func() { defer close(done); e.expiryLoop() }()
		time.Sleep(199 * time.Millisecond)
		synctest.Wait()
		if got := peers(); got != 2 || wakes.Load() != 0 {
			t.Fatalf("1 ms before the window ends: peers=%d wakes=%d, want 2 and 0", got, wakes.Load())
		}
		w.set(time.Now().Add(201 * time.Millisecond)) // the window now ends at 400 ms
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if got := peers(); got != 2 || wakes.Load() != 1 {
			t.Fatalf("at the old instant after an extension: peers=%d wakes=%d, want 2 and 1", got, wakes.Load())
		}
		time.Sleep(199 * time.Millisecond)
		synctest.Wait()
		if got := peers(); got != 2 {
			t.Fatalf("1 ms before the extended window ends: peers=%d, want 2", got)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if got := peers(); got != 0 || wakes.Load() != 2 {
			t.Fatalf("at the extended instant: peers=%d wakes=%d, want 0 and 2", got, wakes.Load())
		}
		for _, k := range keys {
			if e.IsPeer(nodeKey(k)) {
				t.Fatalf("peer %s keeps its lease after the window ended", k.ShortString())
			}
		}
		cancel()
		<-done
	})
}

// Once the window has ended the engine sends no probe, records and publishes no
// confirmation, reports no lease and installs no peer, and a later instant does
// not reopen it.
func TestEndedWindowRefusesDiscovery(t *testing.T) {
	e, keys := confirmationEngine(1)
	k := keys[0]
	w := &windowAt{end: time.Now().Add(time.Hour)}
	e.config.Window = w.until
	var pings atomic.Int64
	e.disco.(*confirmationDisco).ping = func(_ tailcfg.NodeView, _ *ipnstate.PingResult, _ int, cb func(*ipnstate.PingResult)) {
		pings.Add(1)
		cb(&ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
	}
	if _, err := e.ping(t.Context(), k); err != nil {
		t.Fatalf("ping inside the window: %v", err)
	}
	if r, err := e.Registration(); err != nil || len(r.Confirmations) != 1 {
		t.Fatalf("registration inside the window: confirmations=%v err=%v, want one confirmation", r.Confirmations, err)
	}
	peer := e.peerConfig[k]
	w.set(time.Time{})
	if _, err := e.ping(t.Context(), k); err == nil || pings.Load() != 1 {
		t.Fatalf("ping after the window ended: err=%v pings=%d, want an error and still 1 ping", err, pings.Load())
	}
	e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
	if r, err := e.Registration(); err != nil || len(r.Confirmations) != 0 {
		t.Fatalf("registration after the window ended: confirmations=%v err=%v, want none", r.Confirmations, err)
	}
	if e.IsPeer(peer.NodeKey) {
		t.Fatal("the peer keeps its lease after the window ended")
	}
	if err := e.SetPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if e.peer(k).Valid() {
		t.Fatal("a peer update after the window ended installed the peer")
	}
	w.set(time.Now().Add(time.Hour))
	if err := e.SetPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if e.IsPeer(peer.NodeKey) || e.peer(k).Valid() {
		t.Fatal("a later instant reopened an ended window")
	}
}

// Once an engine's window ends it leaves magicsock's peer map, so magicsock
// answers no ping from a peer that still lists it.
func TestEndedWindowStopsAnsweringPings(t *testing.T) {
	w := &windowAt{end: time.Now().Add(time.Hour)}
	a := testEngine(t, Config{Window: w.until})
	b := testEngine(t, Config{})
	pair(t, a, b)
	w.set(time.Time{})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	// The probe loop's next ping finds the window ended and the expiry loop
	// then removes the peer.
	poll(t, ctx, func() bool { return !a.peer(nodePublic(b.PublicKey())).Valid() })
	pingCtx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if r, err := b.ping(pingCtx, nodePublic(a.PublicKey())); err == nil {
		t.Fatalf("an engine whose window ended answered a ping: %+v", r)
	}
}
