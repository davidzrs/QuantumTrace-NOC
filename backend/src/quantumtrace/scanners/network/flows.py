"""Minimal TCP flow reassembly from pcap/pcapng (scapy, no tshark required)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

MAX_STREAM_BYTES = 64 * 1024  # handshakes live at the start of a stream


@dataclass
class Flow:
    a: tuple[str, int]
    b: tuple[str, int]
    syn_dst: tuple[str, int] | None = None
    segments: dict[tuple[str, int], dict[int, bytes]] = field(default_factory=dict)
    first_payload_packet: dict[tuple[str, int], int] = field(default_factory=dict)
    packets: int = 0

    @property
    def server(self) -> tuple[str, int]:
        if self.syn_dst:
            return self.syn_dst
        return self.a if self.a[1] <= self.b[1] else self.b

    @property
    def client(self) -> tuple[str, int]:
        return self.b if self.server == self.a else self.a

    def stream(self, sender: tuple[str, int]) -> bytes:
        out = bytearray()
        for _, data in sorted(self.segments.get(sender, {}).items()):
            out += data
            if len(out) >= MAX_STREAM_BYTES:
                break
        return bytes(out)

    @property
    def client_stream(self) -> bytes:
        return self.stream(self.client)

    @property
    def server_stream(self) -> bytes:
        return self.stream(self.server)


@dataclass
class CaptureStats:
    packets: int = 0
    dns_packets: int = 0
    udp_packets: int = 0
    dns_names: dict[str, str] = field(default_factory=dict)  # IP -> name from A/AAAA answers


def read_flows(path: Path, stats: CaptureStats | None = None) -> Iterator[Flow]:
    from scapy.layers.inet import IP, TCP, UDP  # lazy: scapy import is slow
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    flows: dict[frozenset[tuple[str, int]], Flow] = {}
    stats = stats if stats is not None else CaptureStats()
    with PcapReader(str(path)) as reader:
        for number, pkt in enumerate(reader, start=1):
            stats.packets += 1
            if (udp := pkt.getlayer(UDP)) is not None:
                stats.udp_packets += 1
                if 53 in (int(udp.sport), int(udp.dport)):
                    stats.dns_packets += 1
                    _record_dns_answers(pkt, stats.dns_names)
                continue
            tcp = pkt.getlayer(TCP)
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if tcp is None or ip is None:
                continue
            src, dst = (ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport))
            key = frozenset((src, dst))
            flow = flows.get(key)
            if flow is None:
                flow = flows[key] = Flow(src, dst)
            flow.packets += 1
            flags = int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:  # SYN without ACK: dst is the server
                flow.syn_dst = dst
            payload = bytes(tcp.payload)
            if payload:
                flow.segments.setdefault(src, {}).setdefault(int(tcp.seq), payload)
                flow.first_payload_packet.setdefault(src, number)
    yield from flows.values()


def _record_dns_answers(pkt: object, names: dict[str, str]) -> None:
    """Remember which name each A/AAAA answer resolved to, so servers seen later in the
    capture can be labelled by host name even without TLS SNI (SSH, HTTP, LDAP...)."""
    from scapy.layers.dns import DNS

    dns = pkt.getlayer(DNS)  # type: ignore[attr-defined]
    if dns is None or not dns.qr or not dns.ancount:
        return
    for i in range(int(dns.ancount)):
        try:
            rr = dns.an[i]
        except (IndexError, TypeError):
            break
        if int(getattr(rr, "type", 0)) in (1, 28):  # A, AAAA
            name = (
                rr.rrname.decode(errors="replace")
                if isinstance(rr.rrname, bytes)
                else str(rr.rrname)
            )
            names.setdefault(str(rr.rdata), name.rstrip("."))
