package engine

import (
	"errors"
	"time"
)

var errWindowEnded = errors.New("packet window ended")

// window reads Config.Window and returns the instant the window ends and
// whether it is still open. A nil Window is open with no instant. The first
// read that finds the window ended latches it for the engine's lifetime and
// wakes the expiry loop, which removes every peer from magicsock: magicsock
// has no disco hook of its own, but it sends no disco to, and drops every disco
// frame from, a key that is not in its peer map.
func (e *Engine) window() (time.Time, bool) {
	if e.config.Window == nil {
		return time.Time{}, true
	}
	if e.windowEnded.Load() {
		return time.Time{}, false
	}
	until := e.config.Window()
	if time.Now().Before(until) {
		return until, true
	}
	if e.windowEnded.CompareAndSwap(false, true) {
		signal(e.leaseChanged)
	}
	return time.Time{}, false
}

func (e *Engine) windowOpen() bool {
	_, open := e.window()
	return open
}
