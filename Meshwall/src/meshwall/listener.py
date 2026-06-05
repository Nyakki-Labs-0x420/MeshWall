"""Active port monitoring using scapy to detect scans."""

import asyncio
import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import structlog
from scapy.all import AsyncSniffer, IP, TCP, UDP
from scapy.packet import Packet

from meshwall.config import Config
from meshwall.ipset_manager import IPSetManager
from meshwall.trace import IPTracer
from meshwall.db import SessionLocal
from meshwall.models import BlockedIP

logger = structlog.get_logger()


class ScanDetector:
    """Rule-based port scan detection."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.window = timedelta(seconds=config.scan_threshold_interval)
        self.connections: Dict[str, List[tuple[float, int]]] = defaultdict(list)
        self.suspicious_ips: Set[str] = set()
        self.ipset = IPSetManager(config)
        self.tracer = IPTracer(config)

    def process_packet(self, packet: Packet) -> None:
        if not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        dst_port = None

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags & 0x02:  
                dst_port = tcp.dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            return

        if dst_port is None:
            return

        now = time.time()
        self._add_connection(src_ip, now, dst_port)

        if self._is_scanning(src_ip):
            if src_ip not in self.suspicious_ips:
                self.suspicious_ips.add(src_ip)
                asyncio.create_task(self._handle_scanner(src_ip))

    def _add_connection(self, src_ip: str, timestamp: float, dst_port: int) -> None:
        conns = self.connections[src_ip]
        conns.append((timestamp, dst_port))
        cutoff = timestamp - self.config.scan_threshold_interval
        self.connections[src_ip] = [(ts, port) for ts, port in conns if ts >= cutoff]

    def _is_scanning(self, src_ip: str) -> bool:
        conns = self.connections[src_ip]
        if len(conns) < self.config.scan_threshold_ports:
            return False
        ports = {port for _, port in conns}
        return len(ports) >= self.config.scan_threshold_ports

    async def _handle_scanner(self, src_ip: str) -> None:
        logger.warning("Port scan detected", src_ip=src_ip, ports_scanned=len(self.connections[src_ip]))

        trace_result = await self.tracer.trace(src_ip)
        logger.info("IP traced", src_ip=src_ip, trace=trace_result)

        try:
            db = SessionLocal()
            geo = trace_result.get('geo', {})
            blocked_ip = BlockedIP(
                ip=src_ip,
                reason='port_scan_detected',
                geo_country=geo.get('country'),
                geo_city=geo.get('city'),
                lat=geo.get('latitude'),
                lng=geo.get('longitude'),
                asn=geo.get('asn', ''),
                provider='',
                traceroute=json.dumps(trace_result.get('traceroute', []))
            )
            db.add(blocked_ip)
            db.commit()
            db.close()
        except Exception as e:
            logger.error("Failed to insert BlockedIP into database", error=str(e))

        if self.config.auto_block_enabled:
            self.ipset.add_ip(src_ip, timeout=self.config.auto_block_duration)
            logger.info("Auto-blocked scanner", src_ip=src_ip, duration=self.config.auto_block_duration)


class ListenerDaemon:
    """Capture packets and feed to detector."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.detector = ScanDetector(config)
        self.sniffer: Optional[AsyncSniffer] = None

    async def start(self) -> None:
        logger.info("Starting active listener (scapy)")
        bpf_filter = "(tcp[tcpflags] & tcp-syn != 0) or udp"
        self.sniffer = AsyncSniffer(
            filter=bpf_filter,
            prn=self.detector.process_packet,
            store=False,
        )
        self.sniffer.start()
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.sniffer.stop()
            logger.info("Listener stopped")

    def stop(self) -> None:
        if self.sniffer:
            self.sniffer.stop()