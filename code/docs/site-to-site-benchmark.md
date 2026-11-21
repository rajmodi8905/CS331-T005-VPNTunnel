# Routed site-to-site VPN benchmark

The same two Linux gateways route traffic between two IPv4 LANs in every mode. The N1 fixture provides the LAN and underlay links. Host A and Host B run the probes and traffic generators. The plain IPv4 baseline uses ordinary routes through both gateways. Each VPN provides encrypted forwarding between the same non-overlapping subnets. All modes allow TCP, UDP, and ICMP between those subnets. VPTunnel retains its built-in ACL and flow tracking in addition to the common gateway forwarding policy.

~~~text
10.77.1.57       10.77.1.1        172.31.250.11    172.31.250.12        10.77.2.1       10.77.2.88
  Host A ─ LAN A ─ Gateway A ───────────── underlay ────────────── Gateway B ─ LAN B ─ Host B
~~~

## Software and gateway modes

The measured system is Pop!_OS 24.04 with native Linux `6.18.34-061834-generic`, its matching headers, GCC 14, Rust 1.93.1, and iperf3 3.22. The runner records CPU topology, affinity, governor, and VPN tool versions in `environment.json`.

| Mode | Configuration |
| --- | --- |
| VPTunnel | Build `9152c6f5095ff49203409aa3eb30e409db6ea97c` using the existing demo gateway and controller. The kernel seals packets with ChaCha20-Poly1305 over UDP. [Local protocol](protocol.md) |
| WireGuard | Use the Linux kernel interface and `wg` with a peer route and allowed IPs per remote LAN. [WireGuard Quick Start](https://www.wireguard.com/quickstart/) · [WireGuard namespaces](https://www.wireguard.com/netns/) |
| strongSwan | Two independent IKEv2 daemons with ephemeral PSK authentication. Each negotiates a ChaCha20-Poly1305 ESP child SA bound to an XFRM interface and routes the remote LAN through it. The underlay carries native ESP and has no NAT. [XFRM routing](https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html) · [Cipher proposals](https://docs.strongswan.org/docs/5.9/config/proposals.html) · [Network namespaces](https://docs.strongswan.org/docs/6.0/howtos/nameSpaces.html) |
| OpenVPN | Community Edition 2.7.9. Point-to-point UDP with mutual TLS, an ephemeral EC CA, and a ChaCha20-Poly1305 data channel. The runner requires the kernel `ovpn` device. [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/) · [DCO and point-to-point mode](https://github.com/OpenVPN/openvpn/blob/master/README.dco.md#dco-and-p2p-mode) |

## Reproduction

Build VPTunnel with the matching installed 6.18.y headers and the pinned Rust toolchain. These commands run from `code/`.

~~~bash
sudo apt-get install wireguard-tools strongswan-swanctl charon-systemd \
  libstrongswan-extra-plugins conntrack iproute2 nftables ethtool openssl gcc-14 make
make -C kernel W=1 CC=gcc-14
(cd control && cargo build --release --locked)
~~~

Build iperf3 3.22 from the verified ESnet release tarball and pass the absolute binary path with `--iperf3`. [ESnet release and checksum](https://github.com/esnet/iperf/discussions/2082)

For OpenVPN, use the official Noble `release/2.7` APT repository and the published signing key. The measured version was `2.7.9-noble1`. An extracted package is sufficient for this benchmark. Pass the absolute path to its `usr/sbin/openvpn` to use it alongside the OS package. Linux 6.18.y already provides the `ovpn` module with `CONFIG_OVPN=m` in the measured kernel. The runner starts strongSwan directly in the two gateway namespaces. Disable the host service on a dedicated benchmark machine to avoid starting a third instance. [Official OpenVPN package instructions](https://community.openvpn.net/Pages/OpenVPN%20software%20repos)

~~~bash
sudo env VPTCTL="$PWD/control/target/release/vptctl" taskset -c 0-11 \
  python3 tools/bench_site_to_site.py \
  --iperf3 /path/to/iperf3 \
  --openvpn /path/to/openvpn-2.7/usr/sbin/openvpn \
  --output /tmp/site-to-site-pilot --setup-only

sudo env VPTCTL="$PWD/control/target/release/vptctl" taskset -c 0-11 \
  python3 tools/bench_site_to_site.py \
  --iperf3 /path/to/iperf3 \
  --openvpn /path/to/openvpn-2.7/usr/sbin/openvpn \
  --output /tmp/site-to-site-benchmark

sudo python3 tools/summarize_site_to_site.py /tmp/site-to-site-benchmark
~~~

Use a CPU list appropriate for the host. The measured run used the six performance cores and their siblings on the Intel Core Ultra 7 165H. Namespaces are recreated for each VPN in each repetition. The runner uses temporary identities and removes them at teardown. Local root privileges provide network namespaces and kernel module access. Use a unique output directory for each experiment. Append `--resume` with the original arguments to retry an incomplete run. The runner retains partial cells with an `incomplete` suffix and skips complete cells. The summary tool requires a completed measurement run and writes `summary.md` and `transfers.csv`.

## Measurements

- **TCP goodput.** Unshaped underlay, receiver goodput and sender retransmissions for one and four streams in each direction. Each result uses four measured seconds after two seconds of warm-up.
- **UDP delivery.** A → B at 40, 75, and 90 Mbit/s of offered UDP payload with 64, 512, and 1200 bytes per datagram. Each window is three seconds. A 100 Mbit/s token bucket on each underlay bridge egress counts encapsulation as well as inner traffic and includes Ethernet framing overhead. At a fixed offered payload rate, smaller datagrams consume more link capacity for headers and framing.
- **Latency.** ICMP echo at 20 samples/s before shaping, and while the 75 Mbit/s, 1200-byte UDP case is active after shaping. Each point reports p50 and p95 RTT. Loaded versus idle RTT includes queueing and the change in shaping state. Compare loaded measurements across modes to assess delay at matched demand.
- **CPU.** Sample aggregate and per-core Linux counters at 0.5 seconds. Report busy core-seconds per GiB of receiver payload, plus the busiest core's utilization. Busy time excludes idle and iowait and includes softirq, traffic generation, and other host activity. CPU measurements from five short runs describe this host and traffic profile.
- **Overhead and MTU.** Capture isolated LAN and underlay probes with a 1500-byte underlay. Compare IP packet lengths and check the highest IPv4 DF probe with a reply and one unfragmented underlay packet. The data-plane tests set the gateway routes and both traffic endpoint interfaces to the shared 1428-byte effective inner MTU. The runner verifies each TCP test's negotiated MSS. Boundary probes run in the first repetition. The 92- and 93-byte inner packets expose alignment effects without relying on theoretical header sizes.

TSO, GSO, and GRO are disabled on fixture veth devices for all modes. Repetitions rotate the mode order. The virtual links and shared host make the data useful for relative comparisons on this testbed. A physical gateway installation can have different bandwidth and CPU behavior. [iperf3 options and counters](https://software.es.net/iperf/invoking.html)

The evidence archive includes per-run iperf3 JSON, CPU counters, queue counters, selected packet captures, negotiated-mode evidence, the summarized measurement CSV, and the report.
