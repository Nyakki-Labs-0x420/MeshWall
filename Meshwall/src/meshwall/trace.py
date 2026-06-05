"""IP geolocation and traceroute."""

import asyncio
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import geoip2.database
import structlog

from meshwall.config import Config

logger = structlog.get_logger()


class IPTracer:
    """Trace IPs with geolocation and traceroute."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.geoip_reader: Optional[geoip2.database.Reader] = None
        self._init_geoip()

    def _init_geoip(self) -> None:
        if self.config.geoip_db_path.exists():
            try:
                self.geoip_reader = geoip2.database.Reader(str(self.config.geoip_db_path))
            except Exception as e:
                logger.error("Failed to open GeoIP database", error=str(e))

    async def trace(self, ip: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "src_ip": ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "geo": {},
            "traceroute": [],
        }

        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                result["geo"] = {
                    "country": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
            except Exception:
                pass

        try:
            proc = await asyncio.create_subprocess_exec(
                "traceroute", "-n", "-w", "1", "-q", "1", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode == 0:
                for line in stdout.decode().splitlines():
                    if line.strip() and not line.startswith("traceroute"):
                        parts = line.split()
                        if len(parts) >= 2:
                            hop_ip = parts[1]
                            if hop_ip != "*":
                                result["traceroute"].append(hop_ip)
            else:
                logger.warning("Traceroute failed", ip=ip, error=stderr.decode())
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning("Traceroute error", ip=ip, error=str(e))

        trace_dir = self.config.data_dir / "traces"
        trace_dir.mkdir(exist_ok=True)
        trace_file = trace_dir / f"{ip.replace('.', '_')}.json"
        with open(trace_file, "w") as f:
            json.dump(result, f, indent=2)

        return result