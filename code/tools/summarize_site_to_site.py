#!/usr/bin/env python3
"""Summarize a completed site-to-site benchmark and export a per-run CSV."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import median

from bench_site_to_site import MODES, UDP_RATES, UDP_SIZES

NAMES = dict(zip(MODES, ("Plain IPv4", "VPTunnel", "WireGuard", "strongSwan", "OpenVPN DCO")))


def read(path):
    return json.loads(path.read_text())


def interval(values, precision=2):
    return f"{median(values):.{precision}f} [{min(values):.{precision}f}–{max(values):.{precision}f}]"


def row(items):
    return "| " + " | ".join(map(str, items)) + " |"


def header(items):
    return [row(items), row(["---"] * len(items))]


def collect(output):
    environment = read(output / "environment.json")
    completion = read(output / "completion.json")
    if completion["status"] != "complete" or completion["setup_only"]:
        raise ValueError("Expected a completed measurement run")

    data = defaultdict(list)
    raw = []
    for repetition in range(1, completion["repeats"] + 1):
        for mode in completion["modes"]:
            cell = read(output / f"run-{repetition:02d}" / mode / "cell.json")
            if cell["mode"] != mode or len(cell["measurements"]) != 13:
                raise ValueError(f"Incomplete or mismatched cell for run {repetition}, {mode}")
            data[mode].append(cell)
            for measurement in cell["measurements"]:
                measurement = measurement.copy()
                loaded = measurement.pop("loaded_rtt")
                if measurement["rate_mbps"]:
                    label = measurement["label"]
                    end = read(output / f"run-{repetition:02d}" / mode / label / "iperf.json")["end"]
                    sender = end["sum_sent"]
                    received = measurement["bytes"] // measurement["payload_bytes"]
                    sent = sender["packets"]
                    if not 0 <= received <= sent or sent == 0:
                        raise ValueError(f"Unexpected UDP datagram counts: {mode} {label} run {repetition}")
                    measurement.update(
                        udp_sent_packets=sent,
                        udp_received_packets=received,
                        udp_sender_window_seconds=sender["seconds"],
                        udp_total_loss_pct=100 * (sent - received) / sent,
                        udp_delivered_mbps_per_send_window=measurement["bytes"] * 8 / sender["seconds"] / 1e6,
                    )
                rtt = {f"loaded_{key}": value for key, value in loaded.items()} if loaded else {}
                raw.append(dict(run=repetition, mode=mode, **measurement, **rtt))
    return environment, data, raw


def write_csv(target, rows):
    columns = list(dict.fromkeys(key for record in rows for key in record))
    with target.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def report(env, data, raw):
    modes = list(data)
    transfers = defaultdict(list)
    for record in raw:
        transfers[(record["mode"], record["label"])].append(record)
    tcp_labels = [f"tcp-{streams}-{direction}" for streams in (1, 4)
                  for direction in ("ab", "ba")]
    output = [
        "# Routed site-to-site VPN benchmark",
        "",
        f"Native Linux {env['uname'][2]}, {env['runs']} repetitions per setup, "
        f"{env['inner_mtu']}-byte common inner IPv4 MTU and {env['wire_mtu']}-byte underlay MTU. "
        "Each bracketed range is the minimum and maximum across repetitions.",
        "",
        "## Unshaped TCP receiver goodput",
        "",
        f"Values are Mbit/s. Each transfer targets {env['tcp_seconds']} measured seconds after a "
        "two-second warm-up. The CSV contains the actual receiver durations.",
        "",
        *header(["Setup", "1 stream A → B", "1 stream B → A", "4 streams A → B", "4 streams B → A"]),
    ]
    for mode in modes:
        output.append(row([NAMES[mode]] + [
            interval([r["receiver_mbps"] for r in transfers[(mode, label)]], 0) for label in tcp_labels
        ]))

    output += ["", "### TCP retransmissions", "",
               *header(["Setup", "1 stream A → B", "1 stream B → A", "4 streams A → B", "4 streams B → A"])]
    for mode in modes:
        output.append(row([NAMES[mode]] + [
            interval([r["retransmits"] for r in transfers[(mode, label)]], 0) for label in tcp_labels
        ]))

    output += ["", "## Shaped UDP", "",
               f"A → B on a {env['shaped_mbps']} Mbit/s underlay. Cells give median delivered Mbit/s "
               "and median end-to-end datagram loss. Throughput is received bytes divided by the sender's measured "
               "window. Loss uses the total sent and delivered datagrams, including gaps after the final "
               "received datagram. The CSV retains iperf3's receiver goodput and loss, jitter, and packet rate.",
               "", *header(["UDP payload", "Offered Mbit/s"] + [NAMES[mode] for mode in modes])]
    for size in UDP_SIZES:
        for rate in UDP_RATES:
            values = []
            for mode in modes:
                runs = transfers[(mode, f"udp-{size}-{rate}")]
                median_delivery = median(r["udp_delivered_mbps_per_send_window"] for r in runs)
                median_loss = median(r["udp_total_loss_pct"] for r in runs)
                values.append(f"{median_delivery:.2f} / {median_loss:.2f}%")
            output.append(row([f"{size} B", rate, *values]))

    output += ["", "### RTT and CPU under matched demand", "",
               "The loaded phase sends 75 Mbit/s of 1200-byte UDP payloads. "
               "RTT columns give the median of the per-run percentiles and their ranges, in milliseconds. "
               "Whole-host CPU includes the traffic generators, VPN processing, and background work.",
               "",
               *header(["Setup", "Idle RTT p50", "Idle RTT p95", "Loaded RTT p50", "Loaded RTT p95",
                        "Busy core-s/GiB", "Max core busy %", "UDP jitter ms"])]
    for mode, cells in data.items():
        loaded = transfers[(mode, "udp-1200-75")]
        output.append(row([NAMES[mode]] + [
            interval([cell["idle_rtt"][metric] for cell in cells]) for metric in ("p50_ms", "p95_ms")
        ] + [
            interval([r[f"loaded_{metric}"] for r in loaded]) for metric in ("p50_ms", "p95_ms")
        ] + [
            interval([r[key] for r in loaded]) for key in
            ("core_seconds_per_gib", "busiest_core_pct", "jitter_ms")
        ]))

    output += ["", "## IPv4 encapsulation", "",
               "Each number is the outer IP packet length minus the original IP packet length. "
               "The MTU column gives the largest inner IPv4 echo request carried without fragmentation that got a reply.",
               "", *header(["Setup", "Largest inner IP packet", "92 B inner", "93 B inner",
                            "540 B inner", "1228 B inner"])]
    for mode, cells in data.items():
        first = cells[0]
        output.append(row([NAMES[mode], first["mtu"]] + [x["added_bytes"] for x in first["overhead"]]))

    if "plain" in modes and "vptunnel" in modes and "wireguard" in modes:
        fwd = {mode: median(r["receiver_mbps"] for r in transfers[(mode, "tcp-1-ab")])
               for mode in ("plain", "vptunnel", "wireguard")}
        output += ["", "## VPTunnel comparison", "",
                   f"In the single-stream A → B test, VPTunnel delivered "
                   f"{100*fwd['vptunnel']/fwd['wireguard']:.1f}% of WireGuard's median goodput "
                   f"and {100*fwd['vptunnel']/fwd['plain']:.1f}% of plain IPv4 forwarding's median goodput."]
    return "\n".join(output) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    env, data, raw = collect(args.directory)
    write_csv(args.directory / "transfers.csv", raw)
    (args.directory / "summary.md").write_text(report(env, data, raw))


if __name__ == "__main__":
    main()
