# Shunpike

Shunpike is a Go library that connects peers over a direct UDP path and serves HTTP/3 across it. A coordination service tells each device which peers it may contact. The engine turns that peer list into direct QUIC connections.

## Status

Shunpike is pre-1.0. The exported Go API and the coordination wire protocol can change in any release before 1.0. It targets direct connections between a media server and its clients, and it builds against forks of quic-go and Tailscale (see [Forks](#forks)).

## Goals

On a clean, short path, a transfer over Shunpike should cost as close as possible to a single HTTP/1.1 or HTTP/2 stream over TCP: bytes on the wire, requests, connections and CPU per second of media. On a lossy or long path it should deliver better throughput, startup and seek times than that stream. Judge each change to the engine, `n4` or the forks against both conditions.

## Packages

| Package | What it does |
|---|---|
| `engine` | Wraps one Tailscale magicsock bind behind a `net.PacketConn` that quic-go can use. `Engine.SetPeers` replaces the peer graph, `Engine.Ready` waits for direct evidence in both directions, and `Engine.Path` reports each peer's path class. Relayed data stays denied unless `Config.RelayedDataAllowed` permits the peer. |
| `engine` probes | `ProbeCapabilities` reads local UDP socket facilities and sends no packets. `CheckNAT` observes the NAT through the STUN servers you supply. `ProbePortMapping` discovers UPnP, NAT-PMP and PCP without creating a mapping. Each probe runs only when called and disables Tailscale network namespace binding. |
| `engine/n4` | Serves and dials HTTP/3 over an engine's packet connection. A server closes connections that have no live peer lease and checks the lease again on every request. A client authenticates the peer by a pinned SPKI SHA-256 digest. `Policy` sets the loss profile and receive credit. |
| `engine/coordclient` | `Run` keeps an engine registered with a coordination service and follows its netmap. |
| `engine/cmd/n4peer` | A command that runs an `n4` server or a timed client over a static peer graph. |
| `coordination/protocol` | The wire types and their validation. It uses only the standard library and reads no environment variables. Documents decode strictly and `NetmapVersion` hashes a canonical encoding. `CheckFrame` decides whether to accept, drop or close each signaling frame. |
| `coordination/server` | The `Store` interface with an in-memory implementation, a `Server` for enrollment, registration, presence and held netmap requests, a `Directory` cache, and a `Region` that serves discovery-only DERP streams. |
| `coordination/server/storetest` | A conformance suite for `Store` implementations. |

`coordination/SPEC.md` states the wire rules and limits. The files in `coordination/vectors/` pin them with accepted and refused inputs. Authentication and account policy belong to the application that embeds the server.

## Forks

Shunpike needs behavior that upstream quic-go and Tailscale do not offer. The two forks carry that behavior as patch series on the `main` branch of each fork. Each patch is opt-in unless noted, so a build that sets no option keeps the upstream behavior. `PATCHES.md` in each fork lists every patch with its tests.

### quic-go

[github.com/darthShadow/quic-go](https://github.com/darthShadow/quic-go) patches `v0.64.1`.

- An opt-in BBRv3 congestion sender, chosen with `Config.CongestionControl`. The zero value keeps upstream's sender. Per-connection loss settings select the loss policy.
- A BBRv3 pacer that releases 0.5 ms lumps per wakeup, capped by one GSO buffer and a quarter of the congestion window. The default sender keeps upstream's pacer.
- Optional ACK decimation, set with `Config.ACKDecimation`.
- BBRv3 fixes for paths longer than 100 ms and for receivers that run out of stream credit.
- Path MTU black-hole recovery, set with `Config.PMTUBlackHoleDetection`. Packet connections that are not UDP sockets can opt in to Don't Fragment and GSO through methods.
- A stream gap limit that scales with the receive window, set with `Config.ScaledStreamGapLimit`. Both `n4` default policies enable it; an `n4` server admits only peers with a live lease.
- `Conn.ProbeNow`, which sends PING-only probes while a connection is in PTO backoff.
- A `shunpike_research` build tag that compiles tuning controls and diagnostic counters. Default builds exclude them.

### Tailscale

[github.com/darthShadow/tailscale](https://github.com/darthShadow/tailscale) patches `v1.104.2`.

- `Options.RelayedDataAllowed` decides for each peer whether non-disco data may go over DERP, and `Conn.DERPDataSuppressed` counts refused copies.
- `Options.QUICDontFragment` sets Don't Fragment on every UDP bind, including the socket that replaces one after a rebind.
- `derphttp.Client.StreamDial` and `magicsock.Options.SignalingRegions` let the caller authenticate DERP signaling streams. A region with no nodes returns an error instead of panicking.
- `Options.MaxCallMeMaybeEndpoints` caps the endpoints in each CallMeMaybe message, and the exported `CapEndpoints` makes the same selection.
- `Options.DirectPathRecovery` keeps the best direct address while the endpoint revalidates it after an endpoint change, and never deletes that address. `DirectPathValidatedFunc` reports when a fresh direct pong restores trust.
- A bind fix for every caller: a receive function from a closed `Open` never reads a replaced socket.

## Using Shunpike

A consumer module must add the same two `replace` lines to its own `go.mod`. Go ignores `replace` directives in a dependency's `go.mod`, so the lines in this repository do not reach the consumer.

```
replace github.com/quic-go/quic-go => github.com/darthShadow/quic-go v0.64.1-shunpike.2

replace tailscale.com => github.com/darthShadow/tailscale v1.104.2-shunpike.2
```

## Versions and Tags

Shunpike releases use `vX.Y.Z` tags. A fork tag is `<upstream version>-shunpike.<N>`: `v0.64.1-shunpike.1` is the first release over quic-go `v0.64.1`. `N` numbers the fork's releases over that upstream version. The `replace` lines name the fork tags that this release builds against.

## Checks

CI runs these checks from the repository root with `GOTOOLCHAIN=local` and `GOWORK=off`.

```
go vet ./...
go build ./...
go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run
bash scripts/check-ci.sh
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
```

`scripts/check-ci.sh` checks the `tailscale.com` requirement and that `NOTICE` covers every Linux module license. `govulncheck` fails only when the code calls a vulnerable symbol. CI runs the full workflow on each push and pull request, and every Monday so that a new advisory shows up without a code change.

## License

Shunpike is licensed under BSD-3-Clause. See `LICENSE`. `NOTICE` lists the licenses of third-party modules.
