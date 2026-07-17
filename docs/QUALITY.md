# Streaming quality / throughput

How high-bitrate media (Plex, etc.) throughput is bounded through the data plane,
why it was capped at ~1 Mbps, and the fix.

## Symptom

Video streamed through the reverse proxy to a **remote (WAN)** client was capped
at roughly **1 Mbps** (SD). Low quality played without buffering; anything higher
buffered constantly, and Plex refused to offer higher quality because it had
measured only ~1 Mbps of usable bandwidth. Both host and guest have 1G/1G
internet and the guest has 16 vCPU / 16 GB RAM, so neither the link nor the
hardware was the limit.

## Root cause: TCP congestion control, not the proxy

The cap was **congestion-window collapse from packet loss on the client's WAN last
mile, under `cubic` congestion control** - not anything in the data plane.

Diagnosed with `ss -tin` on the client-facing `:443` socket during a live stream:

```
cubic  rtt:114.8ms  minrtt:101ms  mss:1328
cwnd:8  ssthresh:7
bytes_sent:12,561,123  bytes_retrans:177,952      -> 1.4% retransmitted
send 740,471 bps  delivery_rate 712,488 bps        -> ~0.7 Mbps
Send-Q:80256  notsent:69632  unacked:8
```

Reading this:

- **Congestion-limited, not application-limited.** 80 KB sat queued in the socket
  with 69 KB `notsent` - the proxy had plenty of data ready to hand to TCP. TCP
  would not send it because `cwnd` was pinned at **8 segments (~10 KB)**. Idle
  control sockets showed `app_limited`; the streaming one never did.
- **The cause is loss.** A **1.4%** retransmit rate over a **115 ms** RTT path,
  with **cubic** - which backs off hard on every loss event and cannot reopen the
  window on a long-RTT link.
- **`mss:1328`** (vs the usual 1460) means ~132 B of per-packet overhead in the
  path: a VPN / mobile / encapsulated last mile, which is also where the loss
  originates.

The Mathis model for loss-based congestion control predicts the ceiling:

```
BW  ~=  MSS / (RTT * sqrt(loss))
     =  1328*8 / (0.115 * sqrt(0.014))
     ~=  780 kbps
```

which matches the observed ~0.7-1 Mbps almost exactly. The loss equation, not the
proxy, was dictating the bitrate.

### Why it is provably not the data plane

- **Loopback A/B.** A download **through the data plane** at ~0 RTT (TLS, full
  middleware chain, `curl --resolve ...:127.0.0.1`) matched a **direct-to-backend**
  download of the same object (~21-23 MB/s each). The proxy adds negligible
  overhead; the copy path is not CPU- or throughput-bound.
- **The cap is RTT/loss-sensitive only**, which loopback cannot reproduce. The
  socket evidence above (tiny `cwnd`, high retrans, data queued `notsent`)
  pinpoints TCP, not the application.
- **`FlushInterval` was a red herring.** `dataplane/internal/proxy/server.go`
  sets `FlushInterval: -1` (flush per write). Flushing does not wait for client
  ACKs, so it does not lower the `cwnd/RTT` ceiling. It was **not** changed as
  part of this fix, because the socket was congestion-limited, not
  application-limited.

## Fix: BBR congestion control

BBR is model-based (it estimates bottleneck bandwidth and RTT) rather than
loss-based, so it does **not** collapse the window at a few percent loss the way
cubic does. The data plane is the **sender** for downstream media, so a send-side
congestion-control change on the proxy box is exactly the lever that matters.

BBR ships with the RHEL 9 kernel (`tcp_bbr.ko`) but is not loaded by default;
`tcp_available_congestion_control` starts as `reno cubic`.

### Result (same loss, same RTT, cubic -> bbr)

| Metric         | cubic         | bbr            |
| -------------- | ------------- | -------------- |
| `cwnd`         | 8 segments    | 252 - 1637     |
| delivery_rate  | ~0.7 Mbps     | 8 - 31 Mbps    |
| send rate      | ~0.74 Mbps    | 23 - 156 Mbps  |
| limiting factor| congestion win | often `app_limited` (TCP idle-waiting for more data) |

Roughly a **10-40x** improvement in deliverable throughput, purely from the
congestion-control change. After it, Plex measures the real bandwidth and offers
higher quality.

### Applied automatically by the installer

`install.sh` writes a sysctl drop-in and a modules-load entry, loads the module,
and applies it (see the "kernel network tuning (BBR)" step):

- `/etc/sysctl.d/99-hyproxy-net.conf`
  ```
  net.core.default_qdisc = fq
  net.ipv4.tcp_congestion_control = bbr
  ```
- `/etc/modules-load.d/hyproxy-bbr.conf` -> `tcp_bbr`

### Applying to an already-running box (no reinstall)

Runtime (reverts on reboot):

```bash
sudo modprobe tcp_bbr
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo tc qdisc replace dev "$(ip route show default | awk '{print $5; exit}')" root fq
```

Persist:

```bash
echo tcp_bbr | sudo tee /etc/modules-load.d/hyproxy-bbr.conf
printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' \
  | sudo tee /etc/sysctl.d/99-hyproxy-net.conf
sudo sysctl --system
```

Revert: `sudo sysctl -w net.ipv4.tcp_congestion_control=cubic`.

Congestion control applies to **new** connections only - restart the stream to
pick it up.

## Verifying

While a stream is running, on the proxy box:

```bash
ss -tin state established '( sport = :443 )'
```

Look at the busiest socket (largest `bytes_sent` / non-zero Send-Q):

- **Good:** `bbr`, `cwnd` in the hundreds+, `delivery_rate` well above the stream
  bitrate, frequently `app_limited`.
- **Still bad:** `cubic` or a single-digit `cwnd` with a backed-up Send-Q and
  `notsent` bytes - congestion control has not taken effect (module not loaded,
  or the connection predates the change).

## Caveat: the loss is on the client path

The ~1.4-2% loss and reduced MSS live on the **client's** last-mile path (VPN /
mobile). BBR mitigates it well from the server side, but a genuinely bad client
path is the real source of the ceiling. BBR is the correct server-side lever; it
does not eliminate the loss, it just stops cubic from over-reacting to it.
