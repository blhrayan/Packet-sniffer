#!/usr/bin/env python3


import argparse
import datetime
import sys

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    print(
        "Missing dependency. Install it with:\n"
        "    pip install scapy\n",
        file=sys.stderr,
    )
    sys.exit(1)




stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0,
}


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def describe_packet(packet) -> str:
    """
    Builds a one-line human-readable summary of a captured packet,
    similar in spirit to what tcpdump prints.
    """
    stats["total"] += 1

    # --- ARP (no IP layer) ---
    if ARP in packet:
        stats["arp"] += 1
        arp = packet[ARP]
        op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        return (
            f"[{_timestamp()}] ARP {op:7} {arp.psrc:15} -> {arp.pdst:15} "
            f"(who-has/is-at)"
        )

    # --- IPv4 / IPv6 ---
    ip_layer = None
    if IP in packet:
        ip_layer = packet[IP]
        src, dst = ip_layer.src, ip_layer.dst
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        src, dst = ip_layer.src, ip_layer.dst
    else:
        stats["other"] += 1
        return f"[{_timestamp()}] Non-IP frame ({packet.summary()})"

    if TCP in packet:
        stats["tcp"] += 1
        tcp = packet[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
        return (
            f"[{_timestamp()}] TCP  {src:15}:{tcp.sport:<5} -> "
            f"{dst:15}:{tcp.dport:<5}  flags={flags:<6} len={payload_len}"
        )

    if UDP in packet:
        stats["udp"] += 1
        udp = packet[UDP]
        payload_len = len(bytes(udp.payload)) if udp.payload else 0
        return (
            f"[{_timestamp()}] UDP  {src:15}:{udp.sport:<5} -> "
            f"{dst:15}:{udp.dport:<5}  len={payload_len}"
        )

    if ICMP in packet:
        stats["icmp"] += 1
        icmp = packet[ICMP]
        return (
            f"[{_timestamp()}] ICMP {src:15} -> {dst:15}  "
            f"type={icmp.type} code={icmp.code}"
        )

    stats["other"] += 1
    return f"[{_timestamp()}] IP   {src:15} -> {dst:15}  (other protocol)"


def print_summary():
    print("\n--- Capture summary ---")
    print(f"Total packets : {stats['total']}")
    print(f"  TCP         : {stats['tcp']}")
    print(f"  UDP         : {stats['udp']}")
    print(f"  ICMP        : {stats['icmp']}")
    print(f"  ARP         : {stats['arp']}")
    print(f"  Other       : {stats['other']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_sniffer.py",
        description="Educational packet sniffer built on Scapy. "
                     "Only use on networks/devices you own or are authorized to monitor.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (e.g. eth0, en0, Wi-Fi). "
             "If omitted, Scapy picks a default.",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture before stopping (0 = run until Ctrl+C)",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="bpf_filter",
        help="BPF filter string, e.g. 'tcp port 80', 'udp', 'icmp', 'host 192.168.1.1'",
    )
    parser.add_argument(
        "-w", "--write",
        dest="pcap_out",
        help="Save captured packets to a .pcap file (openable in Wireshark)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print("Starting capture. Press Ctrl+C to stop.")
    if args.bpf_filter:
        print(f"Filter: {args.bpf_filter}")
    print("-" * 70)

    captured = []

    def handle(packet):
        print(describe_packet(packet))
        if args.pcap_out:
            captured.append(packet)

    try:
        sniff(
            iface=args.interface,
            filter=args.bpf_filter,
            prn=handle,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print(
            "\nPermission denied. Packet sniffing needs elevated privileges.\n"
            "Try: sudo python3 packet_sniffer.py",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()
        if args.pcap_out and captured:
            from scapy.all import wrpcap
            wrpcap(args.pcap_out, captured)
            print(f"Saved {len(captured)} packets to {args.pcap_out}")


if __name__ == "__main__":
    main()
