"""Generate a synthetic OT/ICS pcap (Modbus/TCP) for load-testing pcap tools.

Writes directly in libpcap savefile format (no scapy/dpkt dependency) so
generation is fast enough to produce large files. Simulates one HMI/master
polling several PLCs over persistent Modbus/TCP connections, mixing
Read Holding Registers (FC3), Write Single Register (FC6), and Write
Multiple Registers (FC16) so downstream OT analysis (read/write counts,
function code breakdown) has something to report.

Usage:
    python scripts/generate_ot_pcap.py --target-mb 300 --out workspace/artifacts/ot_synthetic_300mb.pcap
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import struct
import time
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

MODBUS_PORT = 502


def checksum16(data: bytes) -> int:
    """Standard one's-complement 16-bit checksum (IP/TCP)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ip_tcp_packet(
    src_mac: bytes, dst_mac: bytes,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    seq: int, ack: int, flags: int,
    payload: bytes,
) -> bytes:
    eth = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)

    ip_total_len = 20 + 20 + len(payload)
    ip_id = random.randint(0, 65535)
    ip_wo_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ip_id, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_csum = checksum16(ip_wo_csum)
    ip_header = ip_wo_csum[:10] + struct.pack("!H", ip_csum) + ip_wo_csum[12:]

    tcp_wo_csum = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        0x50, flags, 8192, 0, 0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, 20 + len(payload),
    )
    tcp_csum = checksum16(pseudo + tcp_wo_csum + payload)
    tcp_header = tcp_wo_csum[:16] + struct.pack("!H", tcp_csum) + tcp_wo_csum[18:]

    return eth + ip_header + tcp_header + payload


# TCP flags
FLAG_SYN = 0x02
FLAG_ACK = 0x10
FLAG_PSH_ACK = 0x18
FLAG_FIN_ACK = 0x11


def mbap(trans_id: int, length: int, unit_id: int = 1) -> bytes:
    return struct.pack("!HHHB", trans_id & 0xFFFF, 0, length, unit_id)


def modbus_read_holding_registers(trans_id: int) -> tuple[bytes, bytes]:
    """FC3 request + response, random start address/quantity."""
    start_addr = random.randint(0, 200)
    qty = random.choice((1, 2, 4, 8, 10))
    req_pdu = struct.pack("!BHH", 3, start_addr, qty)
    request = mbap(trans_id, 1 + len(req_pdu)) + req_pdu

    values = b"".join(struct.pack("!H", random.randint(0, 65535)) for _ in range(qty))
    resp_pdu = struct.pack("!BB", 3, len(values)) + values
    response = mbap(trans_id, 1 + len(resp_pdu)) + resp_pdu
    return request, response


def modbus_write_single_register(trans_id: int) -> tuple[bytes, bytes]:
    """FC6 request + echo response (as per spec, response mirrors request)."""
    addr = random.randint(0, 200)
    value = random.randint(0, 65535)
    pdu = struct.pack("!BHH", 6, addr, value)
    request = mbap(trans_id, 1 + len(pdu)) + pdu
    response = mbap(trans_id, 1 + len(pdu)) + pdu
    return request, response


def modbus_write_multiple_registers(trans_id: int) -> tuple[bytes, bytes]:
    """FC16 request + response (address/quantity echo)."""
    start_addr = random.randint(0, 200)
    qty = random.choice((2, 4, 8))
    values = b"".join(struct.pack("!H", random.randint(0, 65535)) for _ in range(qty))
    req_pdu = struct.pack("!BHHB", 16, start_addr, qty, qty * 2) + values
    request = mbap(trans_id, 1 + len(req_pdu)) + req_pdu

    resp_pdu = struct.pack("!BHH", 16, start_addr, qty)
    response = mbap(trans_id, 1 + len(resp_pdu)) + resp_pdu
    return request, response


MODBUS_BUILDERS = (
    (modbus_read_holding_registers, 0.85),
    (modbus_write_single_register, 0.10),
    (modbus_write_multiple_registers, 0.05),
)


def pick_modbus_builder():
    r = random.random()
    acc = 0.0
    for builder, weight in MODBUS_BUILDERS:
        acc += weight
        if r <= acc:
            return builder
    return MODBUS_BUILDERS[0][0]


class Connection:
    """One persistent Modbus/TCP connection (master -> one PLC)."""

    def __init__(self, master_ip: str, master_mac: bytes, master_port: int,
                 plc_ip: str, plc_mac: bytes):
        self.master_ip = master_ip
        self.master_mac = master_mac
        self.master_port = master_port
        self.plc_ip = plc_ip
        self.plc_mac = plc_mac
        self.client_seq = random.randint(1_000_000, 9_000_000)
        self.server_seq = random.randint(1_000_000, 9_000_000)
        self.trans_id = 0

    def handshake(self, ts: float) -> list[tuple[float, bytes]]:
        pkts = []
        # SYN
        pkts.append((ts, build_ip_tcp_packet(
            self.master_mac, self.plc_mac, self.master_ip, self.plc_ip,
            self.master_port, MODBUS_PORT, self.client_seq, 0, FLAG_SYN, b"")))
        self.client_seq += 1
        ts += 0.0005
        # SYN-ACK
        pkts.append((ts, build_ip_tcp_packet(
            self.plc_mac, self.master_mac, self.plc_ip, self.master_ip,
            MODBUS_PORT, self.master_port, self.server_seq, self.client_seq,
            FLAG_SYN | FLAG_ACK, b"")))
        self.server_seq += 1
        ts += 0.0005
        # ACK
        pkts.append((ts, build_ip_tcp_packet(
            self.master_mac, self.plc_mac, self.master_ip, self.plc_ip,
            self.master_port, MODBUS_PORT, self.client_seq, self.server_seq,
            FLAG_ACK, b"")))
        return pkts

    def poll(self, ts: float) -> list[tuple[float, bytes]]:
        """One request/response Modbus exchange."""
        self.trans_id += 1
        builder = pick_modbus_builder()
        req_payload, resp_payload = builder(self.trans_id)

        pkts = []
        pkts.append((ts, build_ip_tcp_packet(
            self.master_mac, self.plc_mac, self.master_ip, self.plc_ip,
            self.master_port, MODBUS_PORT, self.client_seq, self.server_seq,
            FLAG_PSH_ACK, req_payload)))
        self.client_seq += len(req_payload)

        ts += 0.002
        pkts.append((ts, build_ip_tcp_packet(
            self.plc_mac, self.master_mac, self.plc_ip, self.master_ip,
            MODBUS_PORT, self.master_port, self.server_seq, self.client_seq,
            FLAG_PSH_ACK, resp_payload)))
        self.server_seq += len(resp_payload)
        return pkts


def write_pcap_header(f) -> None:
    f.write(struct.pack(
        "<IHHiIII",
        PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET,
    ))


def write_packet(f, ts: float, buf: bytes) -> int:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(buf), len(buf)))
    f.write(buf)
    return 16 + len(buf)


def mac(last_octet: int) -> bytes:
    return struct.pack("!6B", 0x02, 0x00, 0x00, 0x00, 0x00, last_octet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-mb", type=int, default=300, help="Target file size in MB")
    parser.add_argument("--out", type=str, default="workspace/artifacts/ot_synthetic_300mb.pcap")
    parser.add_argument("--num-plcs", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    target_bytes = args.target_mb * 1024 * 1024
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    master_ip = "192.168.10.10"
    master_mac = mac(0x0A)
    plcs = [
        (f"192.168.10.{20 + i}", mac(0x20 + i))
        for i in range(args.num_plcs)
    ]

    connections = [
        Connection(master_ip, master_mac, 49152 + i, plc_ip, plc_mac)
        for i, (plc_ip, plc_mac) in enumerate(plcs)
    ]

    start_ts = time.time() - 3600  # capture "started" an hour ago
    ts = start_ts
    written = 0
    packet_count = 0

    print(f"Generating OT (Modbus/TCP) pcap -> {out_path} (target {args.target_mb} MB)")

    with open(out_path, "wb") as f:
        write_pcap_header(f)
        written += 24

        # Handshakes for every connection up front.
        for conn in connections:
            for pts, buf in conn.handshake(ts):
                written += write_packet(f, pts, buf)
                packet_count += 1
            ts += 0.001

        conn_idx = 0
        report_every = 50_000
        while written < target_bytes:
            conn = connections[conn_idx % len(connections)]
            conn_idx += 1
            for pts, buf in conn.poll(ts):
                written += write_packet(f, pts, buf)
                packet_count += 1
            ts += random.uniform(0.0005, 0.003)

            if packet_count % report_every == 0:
                pct = min(100.0, written / target_bytes * 100)
                print(f"  {packet_count:,} packets, {written / (1024 * 1024):.1f} MB ({pct:.1f}%)")

    final_size = out_path.stat().st_size
    print(f"Done: {packet_count:,} packets, {final_size / (1024 * 1024):.1f} MB -> {out_path}")


if __name__ == "__main__":
    main()
