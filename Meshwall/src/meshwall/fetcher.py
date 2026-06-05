"""Feed fetching and processing."""

import asyncio
import ipaddress
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

import aiofiles
import aiohttp
import structlog

from meshwall.config import Config
from meshwall.ipset_manager import IPSetManager
from meshwall.iptables_manager import IPTablesManager
from meshwall.db import SessionLocal
from meshwall.models import FeedBlock

logger = structlog.get_logger()


class FeedUpdater:
    """Download, parse, deduplicate, and apply blocklists."""

    def __init__(self, config: Config, debug: bool = False) -> None:
        self.config = config
        self.debug = debug
        self.ipset = IPSetManager(config, debug=debug)
        self.iptables = IPTablesManager(config, debug=debug)
        self.session: Optional[aiohttp.ClientSession] = None
        self.temp_dir = config.data_dir / "temp"
        self.temp_dir.mkdir(exist_ok=True)

    async def run(self, verbose: bool = False) -> None:
        """Main update routine."""
        logger.info("Starting feed update")
        print("Starting feed update...")

        timeout = aiohttp.ClientTimeout(
            total=self.config.fetch_timeout,
            connect=10,
            sock_read=15,
        )

        async with aiohttp.ClientSession(timeout=timeout) as session:
            self.session = session
            tasks = [self._fetch_with_verbose(url, verbose) for url in self.config.feed_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        all_ips: Set[str] = set()
        for i, res in enumerate(results):
            url = self.config.feed_urls[i]
            if isinstance(res, Exception):
                logger.error("Feed fetch failed", url=url, error=str(res))
                print(f"✗ {url}: {res}")
            elif res:
                all_ips.update(res)
                print(f"✓ {url}: {len(res)} entries")

        whitelist = self._load_whitelist()
        all_ips.difference_update(whitelist)

        ip_list = list(all_ips)[: self.config.max_entries]
        logger.info("Processed feeds", total_ips=len(ip_list))
        print(f"Total unique IPs after dedup: {len(ip_list)}")

        if not ip_list:
            print("No IPs to block. Check feeds or network.")
            return

        self._store_in_database(ip_list)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        temp_file = self.temp_dir / f"blocklist_{timestamp}.txt"
        await self._write_ipset_file(temp_file, ip_list)

        if getattr(self.config, 'dry_run', False):
            print(f"Dry run: would swap ipset with {len(ip_list)} entries")
            return

        self.ipset.swap_blocklist(temp_file)
        self.iptables.ensure_rules()

        last_update = self.config.data_dir / "last_update"
        last_update.write_text(datetime.utcnow().isoformat())

        logger.info("Feed update complete")
        print("Update complete.")

    def _store_in_database(self, ip_list: List[str]) -> None:
        """Insert feed IPs into the database (non‑blocking, best effort)."""
        try:
            db = SessionLocal()
            existing_ips = {ip for (ip,) in db.query(FeedBlock.ip).all()}
            new_ips = [ip for ip in ip_list if ip not in existing_ips]
            if new_ips:
                for ip in new_ips:
                    db.add(FeedBlock(ip=ip, source="feed_update"))
                db.commit()
            db.close()
        except Exception as e:
            logger.error("Failed to store feed IPs in database", error=str(e))

    async def _fetch_with_verbose(self, url: str, verbose: bool) -> Set[str]:
        if verbose:
            print(f"Fetching {url}...")
        try:
            return await self.fetch_and_parse(url)
        except Exception as e:
            raise e

    async def fetch_and_parse(self, url: str) -> Set[str]:
        try:
            async with self.session.get(url) as resp:  # type: ignore
                if resp.status != 200:
                    logger.warning("Feed fetch failed", url=url, status=resp.status)
                    return set()
                content = await resp.text()
        except asyncio.TimeoutError:
            logger.error("Feed fetch timeout", url=url)
            return set()
        except aiohttp.ClientError as e:
            logger.error("Feed fetch client error", url=url, error=str(e))
            return set()
        except Exception as e:
            logger.error("Feed fetch unexpected error", url=url, error=str(e))
            return set()

        ips = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", line)
            if match:
                ip_str = match.group(0)
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                    ips.add(str(net))
                except ValueError:
                    continue
        return ips

    def _load_whitelist(self) -> Set[str]:
        whitelist: Set[str] = set()
        whitelist_file = self.config.data_dir / "whitelist.txt"
        if whitelist_file.exists():
            for line in whitelist_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    whitelist.add(line)
        whitelist.update(["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        return whitelist

    async def _write_ipset_file(self, path: Path, ips: List[str]) -> None:
        lines = [
            f"create meshwall-block-new hash:net family inet hashsize 1024 maxelem {self.config.max_entries}\n"
        ]
        for ip in ips:
            lines.append(f"add meshwall-block-new {ip}\n")
        async with aiofiles.open(path, "w") as f:
            await f.writelines(lines)