"""Lightweight port scan detector using kernel NFLOG."""

import asyncio
import json
import os
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

import structlog

from meshwall.config import Config
from meshwall.ipset_manager import IPSetManager
from meshwall.trace import IPTracer
from meshwall.db import SessionLocal
from meshwall.models import BlockedIP

logger = structlog.get_logger()

# Netlink / NFLOG constants
NETLINK_NFLOG = 12
NFLOG_GROUP = 123

# Netlink message types
NLMSG_NOOP = 0x001
NLMSG_ERROR = 0x002
NLMSG_DONE = 0x003

# Netlink header format
NLM_F_REQUEST = 0x001
NLM_F_MULTI = 0x002
NLM_F_ACK = 0x004

# NFLOG message types (subset)
NFULNL_MSG_PACKET = 0x01
NFULNL_MSG_CONFIG = 0x02

# Offsets / sizes for parsing
NLMSG_HDRLEN = 16
NFGEN_HDRLEN = 4
NFULA_PACKET_HDRLEN = 4

# IP protocol numbers
IPPROTO_TCP = 6
IPPROTO_UDP = 17


class LightListener:
    """Listen for TCP SYN and UDP packets via NFLOG using raw netlink socket."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.detector = ScanDetector(config)
        self._running = False
        self._sock: Optional[socket.socket] = None

    async def start(self) -> None:
        """Open netlink socket and read NFLOG messages."""
        logger.info("Starting lightweight NFLOG listener")
        self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NFLOG)
        self._sock.bind((0, NFLOG_GROUP))
        self._running = True

        # Ensure iptables NFLOG rule is present
        self._add_iptables_rules()

        try:
            while self._running:
                data = self._sock.recv(65536)
                if data:
                    self._process_nflog(data)
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        finally:
            self._sock.close()
            self._remove_iptables_rules()
            logger.info("Lightweight listener stopped")

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()

    def _add_iptables_rules(self) -> None:
        """Add NFLOG rules if they don't exist."""
        import subprocess
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--syn", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
            capture_output=True, text=True
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-p", "tcp", "--syn", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
                check=True
            )
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "udp", "-m", "state", "--state", "NEW", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
            capture_output=True, text=True
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "2", "-p", "udp", "-m", "state", "--state", "NEW", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
                check=True
            )

    def _remove_iptables_rules(self) -> None:
        """Remove NFLOG rules when listener stops."""
        import subprocess
        subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--syn", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "udp", "-m", "state", "--state", "NEW", "-j", "NFLOG", "--nflog-group", str(NFLOG_GROUP)],
            capture_output=True
        )

    def _process_nflog(self, data: bytes) -> None:
        """Parse netlink message, extract packet, and feed to detector."""
        try:
            if len(data) < NLMSG_HDRLEN:
                return
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from("=IHHII", data, 0)
            if nlmsg_type != NLMSG_DONE and nlmsg_type != 0:
                # We only care about payload after netlink header
                offset = NLMSG_HDRLEN
                # Generic netlink header (4 bytes: cmd, version, res_id)
                if len(data) < offset + NFGEN_HDRLEN:
                    return
                gen_cmd, gen_version, gen_res_id = struct.unpack_from("=B B H", data, offset)
                offset += NFGEN_HDRLEN
                if gen_cmd == NFULNL_MSG_PACKET:
                    # NFULA_PACKET_HDR (4 bytes: hw_protocol, hook, pad)
                    if len(data) < offset + NFULA_PACKET_HDRLEN:
                        return
                    hw_protocol, hook, pad = struct.unpack_from("=H B B", data, offset)
                    offset += NFULA_PACKET_HDRLEN
                    # parse TLV (type, length) until end
                    while offset + 4 <= len(data):
                        attr_type, attr_len = struct.unpack_from("=HH", data, offset)
                        if attr_len < 4:
                            break
                        if attr_type == 0x01:  # NFULA_PAYLOAD
                            payload_start = offset + 4
                            payload_end = min(offset + attr_len, len(data))
                            packet_data = data[payload_start:payload_end]
                            self._handle_packet(packet_data)
                            break
                        offset += ((attr_len + 3) // 4) * 4  # align to 4 bytes
        except Exception as e:
            logger.error("Error processing NFLOG message", error=str(e))

    def _handle_packet(self, packet: bytes) -> None:
        """Parse IP/TCP/UDP from raw packet and feed detector."""
        try:
            if len(packet) < 20:
                return
            version_ihl = packet[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0x0F) * 4
            if version != 4 or ihl < 20:
                return
            protocol = packet[9]
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])
            if protocol == IPPROTO_TCP and len(packet) >= ihl + 14:
                tcp_offset = ihl
                flags = packet[tcp_offset + 13]
                if flags & 0x02:  # SYN
                    dst_port = struct.unpack_from("!H", packet, tcp_offset + 2)[0]
                    self.detector.process_packet(src_ip, dst_port, "TCP")
            elif protocol == IPPROTO_UDP and len(packet) >= ihl + 4:
                udp_offset = ihl
                dst_port = struct.unpack_from("!H", packet, udp_offset + 2)[0]
                self.detector.process_packet(src_ip, dst_port, "UDP")
        except Exception as e:
            logger.error("Packet parsing error", error=str(e))


class ScanDetector:
    """Rule-based port scan detection (essentailly the same logic tht i used 4 scapy, adapted to receive src_ip, dst_port, proto)."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.window = timedelta(seconds=config.scan_threshold_interval)
        self.connections: Dict[str, List[tuple[float, int]]] = defaultdict(list)
        self.suspicious_ips: Set[str] = set()
        self.ipset = IPSetManager(config)
        self.tracer = IPTracer(config)

    def process_packet(self, src_ip: str, dst_port: int, proto: str) -> None:
        now = time.time()
        self._add_connection(src_ip, now, dst_port)
        if self._is_scanning(src_ip) and src_ip not in self.suspicious_ips:
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

        # Insert into shared database
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
