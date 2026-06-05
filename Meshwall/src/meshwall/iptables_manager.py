"""Manage iptables rules for MeshWall."""

import subprocess
from typing import List

import structlog

from meshwall.config import Config

logger = structlog.get_logger()


class IPTablesManager:
    """Interface to iptables/ip6tables."""

    def __init__(self, config: Config, debug: bool = False) -> None:
        self.config = config
        self.debug = debug
        self.chain = "MESHWALL"
        self.set_name = "meshwall-block"

    def _log_debug(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG: {msg}")

    def _run_cmd(self, cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
        self._log_debug(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)

    def ensure_rules(self) -> None:
        """Ensure the MESHWALL chain and jump rule exist."""
        result = self._run_cmd(["iptables", "-L", self.chain])
        if result.returncode != 0:
            self._run_cmd(["iptables", "-N", self.chain])
            self._run_cmd([
                "iptables", "-A", self.chain, "-m", "set", "--match-set",
                self.set_name, "src", "-j", self.config.default_action
            ])
            check = self._run_cmd(["iptables", "-C", "INPUT", "-j", self.chain])
            if check.returncode != 0:
                self._run_cmd(["iptables", "-I", "INPUT", "1", "-j", self.chain])
            logger.info("Created iptables chain and rules")

        if self.config.ipv6_enabled:
            self._ensure_ip6tables()

    def _ensure_ip6tables(self) -> None:
        result = self._run_cmd(["ip6tables", "-L", self.chain])
        if result.returncode != 0:
            self._run_cmd(["ip6tables", "-N", self.chain])
            self._run_cmd([
                "ip6tables", "-A", self.chain, "-m", "set", "--match-set",
                self.set_name, "src", "-j", self.config.default_action
            ])
            check = self._run_cmd(["ip6tables", "-C", "INPUT", "-j", self.chain])
            if check.returncode != 0:
                self._run_cmd(["ip6tables", "-I", "INPUT", "1", "-j", self.chain])

    def list_meshwall_rules(self) -> List[str]:
        try:
            output = self._run_cmd(["iptables", "-L", self.chain, "-n"]).stdout
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception:
            return []