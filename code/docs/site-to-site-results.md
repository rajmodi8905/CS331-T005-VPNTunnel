# Routed site-to-site VPN benchmark

Native Linux 6.18.34-061834-generic, 5 repetitions per setup, 1428-byte common inner IPv4 MTU and 1500-byte underlay MTU. Each bracketed range is the minimum and maximum across repetitions.

## Unshaped TCP receiver goodput

Values are Mbit/s. Each transfer targets 4 measured seconds after a two-second warm-up. The CSV contains the actual receiver durations.

| Setup | 1 stream A → B | 1 stream B → A | 4 streams A → B | 4 streams B → A |
| --- | --- | --- | --- | --- |
| Plain IPv4 | 5627 [5613–5913] | 5578 [5551–5874] | 20151 [19964–20606] | 18156 [17473–20019] |
| VPTunnel | 1927 [1904–1939] | 1909 [1891–1920] | 3941 [156–4261] | 3851 [3647–4059] |
| WireGuard | 4842 [3455–4996] | 3573 [3548–4820] | 3564 [3247–3695] | 3376 [3273–3619] |
| strongSwan | 1828 [1797–1858] | 1803 [1720–1823] | 5342 [5263–5522] | 4812 [4526–5213] |
| OpenVPN DCO | 2370 [2358–2379] | 2368 [2359–2377] | 8069 [7951–8109] | 6814 [6670–7484] |

### TCP retransmissions

| Setup | 1 stream A → B | 1 stream B → A | 4 streams A → B | 4 streams B → A |
| --- | --- | --- | --- | --- |
| Plain IPv4 | 0 [0–0] | 0 [0–108] | 118 [29–347] | 18 [0–431] |
| VPTunnel | 2 [0–17] | 1 [0–97] | 1032 [18–2905] | 1365 [1104–2120] |
| WireGuard | 194 [21–654] | 255 [8–319] | 1983 [1232–3027] | 1172 [1004–2524] |
| strongSwan | 34 [16–67] | 224 [47–269] | 18710 [16571–19255] | 16034 [13997–18482] |
| OpenVPN DCO | 0 [0–0] | 0 [0–53] | 190 [4–361] | 26 [0–404] |

## Shaped UDP

A → B on a 100 Mbit/s underlay. Cells give median delivered Mbit/s and median end-to-end datagram loss. Throughput is received bytes divided by the sender's measured window. Loss uses the total sent and delivered datagrams, including gaps after the final received datagram. The CSV retains iperf3's receiver goodput and loss, jitter, and packet rate.

| UDP payload | Offered Mbit/s | Plain IPv4 | VPTunnel | WireGuard | strongSwan | OpenVPN DCO |
| --- | --- | --- | --- | --- | --- | --- |
| 64 B | 40 | 39.99 / 0.00% | 31.95 / 20.13% | 33.27 / 16.83% | 34.70 / 13.25% | 35.46 / 11.34% |
| 64 B | 75 | 49.68 / 33.76% | 31.95 / 57.40% | 33.27 / 55.64% | 34.70 / 53.73% | 35.46 / 52.71% |
| 64 B | 90 | 49.68 / 44.80% | 23.21 / 74.21% | 33.27 / 63.03% | 34.70 / 61.26% | 35.46 / 60.59% |
| 512 B | 40 | 39.99 / 0.00% | 39.99 / 0.00% | 40.00 / 0.00% | 40.00 / 0.00% | 40.00 / 0.00% |
| 512 B | 75 | 74.99 / 0.00% | 74.99 / 0.00% | 74.99 / 0.00% | 74.99 / 0.00% | 74.99 / 0.00% |
| 512 B | 90 | 89.26 / 0.81% | 79.36 / 11.80% | 80.37 / 10.70% | 81.37 / 9.57% | 81.89 / 9.00% |
| 1200 B | 40 | 39.99 / 0.00% | 39.99 / 0.00% | 39.99 / 0.00% | 39.99 / 0.00% | 39.99 / 0.00% |
| 1200 B | 75 | 74.98 / 0.00% | 74.99 / 0.00% | 74.98 / 0.00% | 74.99 / 0.00% | 74.99 / 0.00% |
| 1200 B | 90 | 89.98 / 0.00% | 89.99 / 0.00% | 89.99 / 0.00% | 89.99 / 0.00% | 89.99 / 0.00% |

### RTT and CPU under matched demand

The loaded phase sends 75 Mbit/s of 1200-byte UDP payloads. RTT columns give the median of the per-run percentiles and their ranges, in milliseconds. Whole-host CPU includes the traffic generators, VPN processing, and background work.

| Setup | Idle RTT p50 | Idle RTT p95 | Loaded RTT p50 | Loaded RTT p95 | Busy core-s/GiB | Max core busy % | UDP jitter ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Plain IPv4 | 0.08 [0.08–0.09] | 0.14 [0.14–0.15] | 0.04 [0.03–0.04] | 0.04 [0.04–0.05] | 21.34 [15.25–36.99] | 5.46 [3.70–7.05] | 0.00 [0.00–0.00] |
| VPTunnel | 0.13 [0.12–0.13] | 0.22 [0.21–0.23] | 0.06 [0.06–0.06] | 0.07 [0.06–0.07] | 26.30 [18.68–34.69] | 6.35 [5.98–9.60] | 0.00 [0.00–0.00] |
| WireGuard | 0.85 [0.85–0.92] | 1.14 [1.08–1.24] | 0.11 [0.08–0.12] | 0.23 [0.19–0.33] | 42.70 [38.89–45.74] | 5.42 [4.73–8.08] | 0.03 [0.01–0.05] |
| strongSwan | 0.15 [0.15–0.16] | 0.23 [0.19–0.24] | 0.07 [0.05–0.07] | 0.08 [0.08–0.09] | 24.01 [15.63–25.92] | 7.19 [6.06–9.60] | 0.00 [0.00–0.00] |
| OpenVPN DCO | 0.13 [0.13–0.13] | 0.21 [0.20–0.22] | 0.05 [0.03–0.06] | 0.06 [0.06–0.07] | 21.72 [19.82–27.82] | 5.05 [4.39–6.64] | 0.00 [0.00–0.00] |

## IPv4 encapsulation

Each number is the outer IP packet length minus the original IP packet length. The MTU column gives the largest inner IPv4 echo request carried without fragmentation that got a reply.

| Setup | Largest inner IP packet | 92 B inner | 93 B inner | 540 B inner | 1228 B inner |
| --- | --- | --- | --- | --- | --- |
| Plain IPv4 | 1500 | 0 | 0 | 0 | 0 |
| VPTunnel | 1428 | 72 | 72 | 72 | 72 |
| WireGuard | 1440 | 64 | 63 | 64 | 64 |
| strongSwan | 1446 | 56 | 55 | 56 | 56 |
| OpenVPN DCO | 1448 | 52 | 52 | 52 | 52 |

## VPTunnel comparison

In the single-stream A → B test, VPTunnel delivered 39.8% of WireGuard's median goodput and 34.3% of plain IPv4 forwarding's median goodput.

## Findings on this host

- **WireGuard led single-stream TCP and OpenVPN DCO led four-stream TCP among the VPNs.** VPTunnel's median A → B goodput rose from 1.93 to 3.94 Gbit/s with four streams. One four-stream repetition delivered 0.16 Gbit/s, with consecutive one-second receiver intervals showing zero delivery.
- **Small datagrams exposed the cost of headers and forwarding under a packet-rate load.** At 90 Mbit/s offered with 64-byte payloads, even plain forwarding lost 44.8% of datagrams because the 100 Mbit/s shaper counts the complete wire size. VPTunnel had a median loss of 74.2%, compared with WireGuard's 63.0%. VPTunnel's three repetitions above 74% loss also recorded a rejected rekey followed by a fresh handshake in the controller log. Its other two repetitions were near 64.5% loss.
- **The matched 75 Mbit/s, 1200-byte case delivered all datagrams for every setup in all five repetitions.** VPTunnel's loaded p95 RTT was 0.07 ms and its median whole-host CPU cost was 26.30 busy core-seconds per GiB delivered. WireGuard measured 0.23 ms and 42.70 busy core-seconds per GiB in that case. These measurements include traffic generation and background activity on the shared host.

[Reproduction and methodology](site-to-site-benchmark.md) · [Raw evidence and per-run CSV](../results/report-results/site-to-site-2026-11-21.zip)
