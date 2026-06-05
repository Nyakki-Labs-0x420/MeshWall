"""Manage ipsets for blocklists."""

import subprocess
from pathlib import Path
from typing import Dict, List

import structlog

from meshwall.config import Config

logger = structlog.get_logger()


class IPSetManager:
    """Interface to ipset command."""

    def __init__(self, config: Config, debug: bool = False) -> None:
        self.config = config
        self.debug = debug
        self.set_name = "meshwall-block"
        self.temp_set = f"{self.set_name}-new"

    def _log_debug(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG: {msg}")

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        self._log_debug(f"Running: {' '.join(cmd)}")
        try:
            return subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
        except subprocess.TimeoutExpired as e:
            self._log_debug(f"Command timed out: {cmd}")
            raise e

    def swap_blocklist(self, file_path: Path) -> None:
        self._destroy_set(self.temp_set)

        result = self._run_cmd(["ipset", "restore", "-exist", "-file", str(file_path)], timeout=60)
        if result.returncode != 0:
            logger.error("ipset restore failed", stderr=result.stderr)
            return

        result = self._run_cmd(["ipset", "swap", self.temp_set, self.set_name], timeout=10)
        if result.returncode != 0:
            self._rename_set(self.temp_set, self.set_name)
        else:
            self._destroy_set(self.temp_set)

    def _destroy_set(self, name: str) -> None:
        try:
            self._run_cmd(["ipset", "destroy", name], timeout=5)
        except Exception:
            pass

    def _rename_set(self, old: str, new: str) -> None:
        try:
            check = self._run_cmd(["ipset", "list", new], timeout=5)
            if check.returncode == 0:
                self._run_cmd(["ipset", "swap", old, new], timeout=10)
                self._destroy_set(old)
            else:
                self._run_cmd(["ipset", "rename", old, new], timeout=10)
        except Exception as e:
            logger.error("Failed to rename ipset", error=str(e))
            self._ensure_main_set()

    def _ensure_main_set(self) -> None:
        try:
            self._run_cmd(["ipset", "list", self.set_name], timeout=5)
        except subprocess.CalledProcessError:
            self._run_cmd([
                "ipset", "create", self.set_name, "hash:net", "family", "inet",
                "hashsize", "1024", "maxelem", str(self.config.max_entries)
            ], timeout=10)
            logger.info("Created ipset", set=self.set_name)

    def list_sets(self) -> Dict[str, int]:
        result = {}
        try:
            output = self._run_cmd(["ipset", "list"], timeout=5).stdout
            current_set = None
            for line in output.splitlines():
                if line.startswith("Name:"):
                    current_set = line.split(":")[1].strip()
                elif "Number of entries:" in line and current_set:
                    count = int(line.split(":")[1].strip())
                    result[current_set] = count
        except Exception:
            pass
        return result

    def add_ip(self, ip: str, timeout: int = 0) -> bool:
        cmd = ["ipset", "add", self.set_name, ip]
        if timeout > 0:
            cmd.extend(["timeout", str(timeout)])
        try:
            self._run_cmd(cmd, timeout=5)
            return True
        except Exception:
            return False

    def remove_ip(self, ip: str) -> bool:
        try:
            self._run_cmd(["ipset", "del", self.set_name, ip], timeout=5)
            return True
        except Exception:
            return False

    def flush(self) -> None:
        try:
            self._run_cmd(["ipset", "flush", self.set_name], timeout=10)
        except Exception:
            pass

    def swat_blocklist(self, file_path: Path) -> None:
        self.swap_blocklist(file_path)