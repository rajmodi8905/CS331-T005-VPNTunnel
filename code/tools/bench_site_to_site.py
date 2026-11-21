#!/usr/bin/env python3
"""Compare routed IPv4 site-to-site VPNs with the same forwarding fixture."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import bench_capacity_cpu as capacity
import bench_netns as vpt

MODES = ("plain", "vptunnel", "wireguard", "strongswan", "openvpn")
SITES = {
    "a": ("gwa", "10.77.1.0/24", "172.31.250.11", "10.78.0.1"),
    "b": ("gwb", "10.77.2.0/24", "172.31.250.12", "10.78.0.2"),
}
DEVICES = {"vptunnel": "vpn0", "wireguard": "wgbench", "strongswan": "ipsecbench",
           "openvpn": "ovpnbench"}
INNER_MTU = 1428
SHAPED_MBPS = 100
UDP_SIZES = (64, 512, 1200)
UDP_RATES = (40, 75, 90)
MODULES = ("veth", "sch_tbf", "wireguard", "xfrm_interface", "esp4",
           "chacha20poly1305", "ovpn")

dump = capacity.dump


def execute(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], capture_output=True, text=True,
                          timeout=30, check=True, **kwargs).stdout


def stop(process, signum=signal.SIGTERM):
    if process.poll() is None:
        process.send_signal(signum)
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)


def stats_ping(text, sent):
    times = [float(value) for value in re.findall(r"time[=<]([\d.]+) ms", text)]
    times.sort()
    return {
        "sent": sent, "received": len(times),
        "p50_ms": quantile(times, .5), "p95_ms": quantile(times, .95),
    }


def quantile(values, fraction):
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def pcap_ipv4(content):
    """Parse the Ethernet IPv4 headers, skipping non-IPv4 packets."""
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(content[:4])
    if endian is None or struct.unpack_from(endian + "I", content, 20)[0] & 0xffff != 1:
        raise ValueError("Expected an Ethernet pcap")
    offset = 24
    while offset < len(content):
        included = struct.unpack_from(endian + "I", content, offset + 8)[0]
        frame = content[offset + 16:offset + 16 + included]
        offset += 16 + included
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        yield (str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20])),
               int.from_bytes(ip[2:4], "big"), ip[9],
               bool(int.from_bytes(ip[6:8], "big") & 0x3fff), ip[(ip[0] & 15) * 4:])


def capture_socket(namespace, interface):
    with vpt.D.netns(namespace):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((interface, 0))
        sock.setblocking(False)
    return sock


def capture_bytes(sock):
    capture = io.BytesIO()
    capture.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    while True:
        try:
            frame, address = sock.recvfrom(65535)
        except BlockingIOError:
            return capture.getvalue()
        if address[2] == socket.PACKET_OUTGOING:
            timestamp = time.time_ns() // 1000
            capture.write(struct.pack("<IIII", *divmod(timestamp, 1000000), len(frame), len(frame)))
            capture.write(frame)


class Lab(capacity.Experiment):
    """One clean instance of the repository's routed N1 fixture."""

    def __init__(self, output, mode, openvpn, iperf):
        super().__init__(SimpleNamespace(output=output, resume=False))
        self.mode_name = mode
        self.openvpn = openvpn
        self.iperf = iperf
        self.processes = []
        self.namespace_dirs = []

    def background(self, ns, name, *args):
        with (self.out / f"{name}.log").open("w") as log:
            process = subprocess.Popen(["ip", "netns", "exec", vpt.D.NS[ns], *map(str, args)],
                                       stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def await_ready(self, description, check):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(.1)
        raise RuntimeError(f"{description} did not become ready. See logs in {self.out}")

    def routes(self, common_mtu=None):
        for side, peer in (("a", "b"), ("b", "a")):
            ns, _, _, _ = SITES[side]
            _, subnet, outer, tunnel_ip = SITES[peer]
            device = DEVICES.get(self.mode_name, f"veth_gw{side}_out")
            route = [subnet, "dev", device]
            if self.mode_name in ("plain", "openvpn"):
                route.extend(("via", outer if self.mode_name == "plain" else tunnel_ip))
            if common_mtu:
                route.extend(("mtu", common_mtu, "advmss", common_mtu - 40))
            self.ns(ns, "ip", "route", "replace", *route)

    def access_policy(self):
        for side, peer in (("a", "b"), ("b", "a")):
            ns, local, _, _ = SITES[side]
            _, remote, _, _ = SITES[peer]
            lan = f"veth_gw{side}_lan"
            uplink = DEVICES.get(self.mode_name, f"veth_gw{side}_out")
            rules = f"""table inet vpn_bench {{
    chain forward {{
        type filter hook forward priority 5; policy drop;
        iifname "{lan}" oifname "{uplink}" ip saddr {local} ip daddr {remote} ip protocol {{tcp, udp, icmp}} accept
        iifname "{uplink}" oifname "{lan}" ip saddr {remote} ip daddr {local} ip protocol {{tcp, udp, icmp}} accept
    }}
}}
"""
            path = Path(self.tmp.name) / f"filter-{side}.nft"
            path.write_text(rules)
            self.ns(ns, "nft", "-f", path)

    def configure_wireguard(self):
        private, public = {}, {}
        for side in SITES:
            key = execute("wg", "genkey")
            private[side] = Path(self.tmp.name) / f"wg-{side}.key"
            private[side].write_text(key)
            private[side].chmod(0o600)
            public[side] = execute("wg", "pubkey", input=key).strip()
        for side, peer in (("a", "b"), ("b", "a")):
            ns = SITES[side][0]
            _, subnet, outer, _ = SITES[peer]
            self.ns(ns, "ip", "link", "add", "wgbench", "type", "wireguard")
            self.ns(ns, "wg", "set", "wgbench", "listen-port", 51820,
                    "private-key", private[side], "peer", public[peer],
                    "allowed-ips", subnet, "endpoint", f"{outer}:51820")
            self.ns(ns, "ip", "link", "set", "wgbench", "mtu", 1440, "up")

    def configure_strongswan(self):
        work = Path(self.tmp.name)
        psk = secrets.token_hex(32)
        sockets = {}
        for side, peer in (("a", "b"), ("b", "a")):
            ns, local, outer, _ = SITES[side]
            _, remote, peer_outer, _ = SITES[peer]
            self.ns(ns, "ip", "link", "add", "ipsecbench", "type", "xfrm",
                    "dev", f"veth_gw{side}_out", "if_id", 42)
            self.ns(ns, "ip", "link", "set", "ipsecbench", "up")
            socket = work / f"ike-{side}.sock"
            sockets[side] = f"unix://{socket}"
            settings = work / f"strongswan-{side}.conf"
            settings.write_text(f"""
charon-systemd {{
    load = random nonce aes sha1 sha2 hmac kdf chapoly curve25519 kernel-netlink socket-default vici
    install_routes = no
    plugins {{
        vici {{
            socket = {sockets[side]}
        }}
    }}
}}
""")
            # ip netns exec binds this directory over /etc/swanctl only in this
            # namespace. The package's AppArmor policy still governs swanctl.
            ns_dir = Path("/etc/netns") / vpt.D.NS[ns]
            ns_dir.mkdir(mode=0o700, parents=True)
            self.namespace_dirs.append(ns_dir)
            cfg_dir = ns_dir / "swanctl"
            cfg_dir.mkdir(mode=0o700)
            cfg = cfg_dir / "swanctl.conf"
            cfg.write_text(f"""
connections {{
    site {{
        version = 2
        local_addrs = {outer}
        remote_addrs = {peer_outer}
        proposals = aes256-sha256-curve25519
        mobike = no
        local {{
            auth = psk
            id = {outer}
        }}
        remote {{
            auth = psk
            id = {peer_outer}
        }}
        children {{
            lan {{
                mode = tunnel
                local_ts = {local}
                remote_ts = {remote}
                esp_proposals = chacha20poly1305
                if_id_in = 42
                if_id_out = 42
            }}
        }}
    }}
}}
secrets {{
    ike-sites {{
        id-a = {outer}
        id-b = {peer_outer}
        secret = 0x{psk}
    }}
}}
""")
            cfg.chmod(0o600)
            self.background(ns, f"charon-{side}", "env", f"STRONGSWAN_CONF={settings}",
                            "charon-systemd")
            self.await_ready(f"VICI socket for {side}", socket.exists)
            loaded = self.ns(ns, "swanctl", "--load-all", "--noprompt", "--uri", sockets[side])
            if "loaded connection 'site'" not in loaded.stdout:
                raise RuntimeError(f"strongSwan site {side} did not load its connection: {loaded.stdout}")
        self.ns("gwa", "swanctl", "--initiate", "--child", "lan", "--timeout", 10,
                "--uri", sockets["a"])
        report = self.ns("gwa", "swanctl", "--list-sas", "--uri", sockets["a"]).stdout
        if not re.search(r"INSTALLED, TUNNEL.*CHACHA20_POLY1305", report):
            raise RuntimeError(f"Expected an installed ChaCha20-Poly1305 ESP SA:\n{report}")

    def configure_openvpn(self):
        work = Path(self.tmp.name)
        ca_key, ca_crt = work / "ca.key", work / "ca.crt"
        execute("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=VPN benchmark CA",
                "-days", 2, "-keyout", ca_key, "-out", ca_crt)
        for side, peer in (("b", "a"), ("a", "b")):
            ns, _, outer, tunnel_ip = SITES[side]
            _, _, peer_outer, peer_tunnel_ip = SITES[peer]
            role = "client" if side == "a" else "server"
            peer_role = "server" if side == "a" else "client"
            key, csr, crt = (work / f"ovpn-{side}.{ext}" for ext in ("key", "csr", "crt"))
            extensions = work / f"ext-{side}.cnf"
            extensions.write_text(f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
                                  f"extendedKeyUsage={role}Auth\n")
            execute("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN=site-{side}",
                    "-keyout", key, "-out", csr)
            execute("openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
                    "-CAcreateserial", "-days", 2, "-extfile", extensions, "-out", crt)
            cfg = work / f"ovpn-{side}.conf"
            cfg.write_text(f"""
dev ovpnbench
dev-type tun
proto udp4
local {outer} 1194
remote {peer_outer} 1194
topology subnet
ifconfig {tunnel_ip} 255.255.255.252
tun-mtu 1450
ca {ca_crt}
cert {crt}
key {key}
tls-{role}
remote-cert-tls {peer_role}
verify-x509-name site-{peer} name
data-ciphers CHACHA20-POLY1305
verb 3
""" + ("dh none\n" if role == "server" else ""))
            self.background(ns, f"openvpn-{side}", self.openvpn, "--config", cfg)
        for side, (ns, _, _, _) in SITES.items():
            log = self.out / f"openvpn-{side}.log"
            self.await_ready(f"OpenVPN site {side}", lambda: "Initialization Sequence Completed"
                             in log.read_text())
            link = json.loads(self.ns(ns, "ip", "-j", "-d", "link", "show", "ovpnbench").stdout)
            if link[0]["linkinfo"]["info_kind"] != "ovpn":
                raise RuntimeError(f"OpenVPN site {side} is using a userspace device")
            if "CHACHA20-POLY1305" not in log.read_text():
                raise RuntimeError(f"OpenVPN site {side} did not negotiate ChaCha20-Poly1305")

    def configure(self):
        for ns, _, _, _ in SITES.values():
            self.ns(ns, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        if self.mode_name == "vptunnel":
            for gateway in self.gateways:
                result = gateway.script("up", *(("--wait", "12") if gateway.site == "gwa" else ()))
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
        elif self.mode_name != "plain":
            getattr(self, f"configure_{self.mode_name}")()
        self.routes()
        self.access_policy()
        for src, dst in (("ha", vpt.HB), ("hb", vpt.HA)):
            self.ns(src, "ping", "-n", "-I", vpt.HA if src == "ha" else vpt.HB, "-c", 3, "-i", .15, "-w", 4, dst)
        for ns, _, _, _ in SITES.values():
            self.ns(ns, "ip", "-j", "route", "show")
            self.ns(ns, "ip", "-j", "-d", "link", "show")

    def ping(self, payload, src="ha", dst=vpt.HB):
        return self.ns(src, "ping", "-n", "-I", vpt.HA if src == "ha" else vpt.HB, "-c", 1, "-W", 1, "-M", "do",
                       "-s", payload, dst, check=False).returncode == 0

    def wire_packet_sizes(self, capture, inner):
        sizes = []
        for src, dst, size, protocol, fragment, data in pcap_ipv4(capture):
            plain = (src, dst, protocol) == (vpt.HA, vpt.HB, 1) and data[:1] == b"\x08"
            outer = (src, dst) == (SITES["a"][2], SITES["b"][2])
            if plain and self.mode_name != "plain":
                raise RuntimeError("Observed plaintext ICMP on the encrypted underlay")
            if fragment and (plain or outer):
                return []
            # Select data messages and omit smaller keepalives from the capture.
            encrypted = outer and (
                (self.mode_name == "strongswan" and protocol == 50) or
                (protocol == 17 and (
                    (self.mode_name == "vptunnel" and data[8:13] == b"VPT1\x03") or
                    (self.mode_name == "wireguard" and data[8:12] == b"\x04\0\0\0") or
                    (self.mode_name == "openvpn" and data[8:9] == b"\x48"))))
            if plain or (encrypted and size >= inner):
                sizes.append(size)
        return sizes

    def unfragmented(self, payload):
        with capture_socket("und", "veth_und_b") as underlay:
            if not self.ping(payload):
                return False
            sizes = self.wire_packet_sizes(capture_bytes(underlay), payload + 28)
        return len(sizes) == 1 and sizes[0] <= 1500

    def mtu(self):
        low, high = 0, 1473
        while high - low > 1:
            mid = (low + high) // 2
            if self.unfragmented(mid):
                low = mid
            else:
                high = mid
        if not self.unfragmented(low) or self.unfragmented(high):
            raise RuntimeError("DF MTU probe was unstable")
        return low + 28

    def overhead(self):
        rows = []
        for payload in (64, 65, 512, 1200):
            path = self.out / f"icmp-{payload}.pcap"
            lan_path = self.out / f"icmp-{payload}-lan.pcap"
            with capture_socket("ha", "veth_ha") as lan, \
                    capture_socket("und", "veth_und_b") as underlay:
                if not self.ping(payload):
                    raise RuntimeError("ICMP overhead probe did not reach site B")
                lan_data = capture_bytes(lan)
                wire_data = capture_bytes(underlay)
            lan_path.write_bytes(lan_data)
            path.write_bytes(wire_data)
            inner_packets = [size for src, dst, size, protocol, frag, data in pcap_ipv4(lan_data)
                             if (src, dst, protocol, frag) == (vpt.HA, vpt.HB, 1, False)
                             and data[:1] == b"\x08"]
            if inner_packets != [payload + 28]:
                raise RuntimeError(f"Expected one unfragmented request in {lan_path}")
            inner = inner_packets[0]
            matches = self.wire_packet_sizes(wire_data, inner)
            if len(matches) != 1:
                raise RuntimeError(f"Expected one ICMP data packet in {path}, found {matches}")
            rows.append(dict(icmp_payload_bytes=payload, inner_ip_bytes=inner,
                             outer_ip_bytes=matches[0], added_bytes=matches[0]-inner))
        return rows

    def idle_rtt(self):
        cpu = capacity.CPU().start()
        try:
            ping = self.ns("ha", "ping", "-n", "-I", vpt.HA, "-D", "-i", .05, "-c", 100, vpt.HB)
        finally:
            idle_cpu = cpu.finish(self.out / "cpu-idle.json")
            dump(self.out / "cpu-idle-summary.json", idle_cpu)
        return stats_ping(ping.stdout, 100)

    def measure(self, label, seconds, *, reverse=False, streams=1, rate=None, size=None):
        folder = self.out / label
        folder.mkdir()
        self.qstats(folder / "qdisc-before.json")
        srv_args = ["ip", "netns", "exec", vpt.D.NS["hb"],
                    str(self.iperf), "-s", "-1", "-B", vpt.HB]
        with (folder / "server.log").open("w") as log:
            server = subprocess.Popen(srv_args, stdout=log, stderr=subprocess.STDOUT)
        cpu = None
        try:
            self.await_ready("iperf3 listener", lambda: ":5201" in
                             self.ns("hb", "ss", "-Hln", "sport", "=", ":5201").stdout)
            args = ["ip", "netns", "exec", vpt.D.NS["ha"], str(self.iperf), "-c", vpt.HB,
                    "-B", vpt.HA, "-J", "--get-server-output", "-t", str(seconds)]
            if reverse:
                args.append("-R")
            if rate:
                args.extend(("-u", "-b", f"{rate}M", "-l", str(size)))
            else:
                args.extend(("-P", str(streams), "-O", "2"))
            cpu = capacity.CPU().start()
            if rate == 75 and size == 1200:
                with (folder / "ping.txt").open("w") as log:
                    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True) as client:
                        time.sleep(.35)
                        ping_count = int((seconds - .6) / .05)
                        ping = subprocess.Popen(["ip", "netns", "exec", vpt.D.NS["ha"], "ping",
                                                 "-n", "-I", vpt.HA, "-D", "-i", ".05", "-c", str(ping_count),
                                                 "-w", str(seconds), vpt.HB], stdout=log, stderr=log)
                        try:
                            stdout, stderr = client.communicate(timeout=seconds + 10)
                        except subprocess.TimeoutExpired:
                            stop(client)
                            raise
                        finally:
                            try:
                                ping.wait(timeout=seconds + 1)
                            except subprocess.TimeoutExpired:
                                stop(ping, signal.SIGINT)
                    result = subprocess.CompletedProcess(args, client.returncode, stdout, stderr)
                rtt = stats_ping((folder / "ping.txt").read_text(), ping_count)
            else:
                result = subprocess.run(args, capture_output=True, text=True, timeout=seconds + 15)
                rtt = None
            (folder / "iperf.json").write_text(result.stdout)
            dump(folder / "command.json", dict(argv=args, stderr=result.stderr, code=result.returncode))
            result.check_returncode()
            iperf = json.loads(result.stdout)
            if iperf.get("error"):
                raise RuntimeError(iperf["error"])
        finally:
            stop(server)
            if cpu:
                cpu_summary = cpu.finish(folder / "cpu.json", omit=0 if rate else 2)
                dump(folder / "cpu-summary.json", cpu_summary)
        self.qstats(folder / "qdisc-after.json")
        recv = iperf["end"]["sum_received"]
        sender = iperf["end"]["sum_sent"]
        delivered = recv["bytes"]
        mss = iperf["start"].get("tcp_mss_default") if not rate else None
        if not rate and mss not in (INNER_MTU - 40, INNER_MTU - 52):
            raise RuntimeError(f"Unexpected TCP MSS for common inner MTU: {mss}")
        return dict(label=label, receiver_mbps=recv["bits_per_second"]/1e6, bytes=delivered,
                    offered_mbps=sender["bits_per_second"]/1e6, rate_mbps=rate, payload_bytes=size,
                    receiver_seconds=recv["seconds"], tcp_mss=mss,
                    jitter_ms=recv.get("jitter_ms"), loss_pct=recv.get("lost_percent"),
                    delivered_pps=(recv["packets"] - recv["lost_packets"])/recv["seconds"]
                    if rate else None, retransmits=sender.get("retransmits"),
                    busy_core_seconds=cpu_summary["busy_cpu_seconds"],
                    busiest_core_pct=cpu_summary["busiest_core_pct"],
                    core_seconds_per_gib=cpu_summary["busy_cpu_seconds"] * 2**30 / delivered
                    if delivered else None, loaded_rtt=rtt)

    def close(self):
        for process in reversed(self.processes):
            stop(process)
        if self.setup_attempted:
            if self.mode_name == "vptunnel":
                for gateway in self.gateways:
                    gateway.script("down")
                    log = Path(gateway.env["VPT_RUN_DIR"]) / "controller.log"
                    if log.exists():
                        shutil.copyfile(log, self.out / f"vpt-{gateway.site}.log")
            self.call(["bash", Path(vpt.NETNS) / "n1_fixture.sh", "teardown", vpt.D.RUN])
        for namespace_dir in self.namespace_dirs:
            shutil.rmtree(namespace_dir)
        if self.tmp:
            self.tmp.cleanup()

    def run(self, args, first):
        data = dict(mode=self.mode_name)
        try:
            self.setup()
            self.configure()
            self.offloads()
            if first:
                data["mtu"] = self.mtu()
                if data["mtu"] < INNER_MTU:
                    raise RuntimeError(f"{self.mode_name} does not support {INNER_MTU}-byte inner packets")
                data["overhead"] = self.overhead()
            self.routes(INNER_MTU)
            # Both TCP peers need the same effective MTU before SYN/SYN-ACK.
            for host in ("ha", "hb"):
                self.ns(host, "ip", "link", "set", f"veth_{host}", "mtu", INNER_MTU)
            if not self.ping(INNER_MTU - 28):
                raise RuntimeError("Common inner MTU is not reachable")
            if not args.setup_only:
                data["idle_rtt"] = self.idle_rtt()
                for ns, _, _, _ in SITES.values():
                    self.ns(ns, "nft", "list", "ruleset")
                self.qstats(self.out / "unshaped-qdisc.json")
                data["measurements"] = [
                    self.measure(f"tcp-{streams}-{'ba' if reverse else 'ab'}", args.tcp_seconds,
                                 streams=streams, reverse=reverse)
                    for streams in (1, 4) for reverse in (False, True)
                ]
                self.shape(SHAPED_MBPS)
                self.qstats(self.out / "shaped-qdisc.json")
                for size in UDP_SIZES:
                    for rate in UDP_RATES:
                        data["measurements"].append(
                            self.measure(f"udp-{size}-{rate}", args.udp_seconds, rate=rate, size=size)
                        )
        finally:
            self.close()
        dump(self.out / "cell.json", data)


@contextmanager
def module_scope(module):
    # Only unload the VPT module if this runner loaded it. Keep peer-independent
    # kernel modules loaded across measurements so that repeats see the same host.
    for name in MODULES:
        execute("modprobe", name)
    already_loaded = Path("/sys/module/vpt1_foundation").exists()
    if already_loaded:
        raise RuntimeError("Unload the pre-existing VPTunnel module before comparing this checkout")
    execute("insmod", module)
    try:
        yield
    finally:
        execute("rmmod", "vpt1_foundation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iperf3", default=Path(shutil.which("iperf3") or "iperf3"), type=Path)
    parser.add_argument("--openvpn", type=Path, default=Path("/usr/sbin/openvpn"))
    parser.add_argument("--modes", choices=MODES, nargs="+", default=MODES)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--tcp-seconds", type=int, default=4)
    parser.add_argument("--udp-seconds", type=int, default=3)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--setup-only", action="store_true")
    args = parser.parse_args()
    if os.geteuid() or not os.uname().release.startswith("6.18."):
        parser.error("Run as root on native Linux 6.18.y with matching kernel headers")
    if args.runs < 1 or args.tcp_seconds < 2 or args.udp_seconds < 2:
        parser.error("Use a positive repetition count and measurement windows of at least two seconds")
    if len(args.modes) != len(set(args.modes)):
        parser.error("Each mode may be selected once")
    args.openvpn = args.openvpn.resolve()
    args.iperf3 = args.iperf3.resolve()
    if not vpt.VPTCTL or not Path(vpt.VPTCTL).is_file():
        parser.error("Set VPTCTL to the built controller executable")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=args.resume)
    versions = {"iperf3": execute(args.iperf3, "--version"), "wg": execute("wg", "--version"),
                "openvpn": execute(args.openvpn, "--version"),
                "strongswan": execute("dpkg-query", "-W", "-f=${Version}", "strongswan-swanctl")}
    environment = dict(versions=versions, uname=list(os.uname()),
         lscpu=execute("lscpu"), affinity=sorted(os.sched_getaffinity(0)),
         governor=Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
         if Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").exists() else None,
         runs=args.runs, modes=list(args.modes), setup_only=args.setup_only,
         tcp_seconds=args.tcp_seconds, udp_seconds=args.udp_seconds,
         inner_mtu=INNER_MTU, wire_mtu=1500, shaped_mbps=SHAPED_MBPS)
    env_path = output / "environment.json"
    if env_path.exists():
        previous = json.loads(env_path.read_text())
        if any(previous.get(key) != value for key, value in environment.items() if key != "lscpu"):
            parser.error("Resume requires the original benchmark environment and arguments")
    else:
        dump(env_path, dict(**environment, started_utc=datetime.now(timezone.utc).isoformat()))
    count = 1 if args.setup_only else args.runs
    with module_scope(vpt.MODULE):
        for index in range(count):
            shift = index % len(args.modes)
            for mode in args.modes[shift:] + args.modes[:shift]:
                cell = output / f"run-{index+1:02d}" / mode
                if (cell / "cell.json").exists():
                    continue
                if cell.exists():
                    cell.rename(cell.with_name(f"{mode}-incomplete-{time.time_ns()}"))
                print(f"Run {index+1}/{count}: {mode}", flush=True)
                Lab(cell, mode, args.openvpn, args.iperf3).run(args, index == 0)
    dump(output / "completion.json", dict(status="complete", repeats=count,
                                          modes=list(args.modes), setup_only=args.setup_only))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
