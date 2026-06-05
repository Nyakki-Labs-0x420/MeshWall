"""Configuration handling for MeshWall."""

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()


def _get_writable_path(system_path: Path, env_var: str, fallback_suffix: str, is_dir: bool = True) -> Path:
    """Return a writable path, preferring env var, then system if writable, else user dir.
    
    Args:
        system_path: The ideal system-level path.
        env_var: Name of environment variable that can override the path.
        fallback_suffix: Suffix to append to ~ if system path is not writable.
        is_dir: True if the path is a directory, False if it's a file.
    """
    if env_var in os.environ:
        return Path(os.environ[env_var])

    # Try sys path 1st
    try:
        if is_dir:
            system_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            system_path.parent.mkdir(parents=True, exist_ok=True)
        # Test writability by creating a temp file/dir
        test_path = system_path.parent / ".meshwall_write_test"
        test_path.touch()
        test_path.unlink()
        return system_path
    except (PermissionError, OSError):
        # Fallback to user dir
        user_path = Path.home() / fallback_suffix
        # Ensure the parent dir exists (for files) or the dir itself (for dirs)
        if is_dir:
            user_path.mkdir(parents=True, exist_ok=True)
        else:
            user_path.parent.mkdir(parents=True, exist_ok=True)
        return user_path


@dataclass
class Config:
    """MeshWall configuration."""

    # Paths
    config_file: Path = Path("/etc/meshwall/meshwall.conf")
    data_dir: Path = Path("/var/lib/meshwall")
    run_dir: Path = Path("/run/meshwall")
    log_file: Path = Path("/var/log/meshwall/meshwall.log")
    geoip_db_path: Path = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
    ml_model_path: Optional[Path] = None
    dnsmasq_config: Path = Path("/etc/dnsmasq.d/meshwall-block.conf")
    database_path: Path = Path("/var/lib/meshwall/meshwall.db")

    # Gen
    update_frequency: str = "daily"
    update_time: str = "03:00"
    max_entries: int = 200000
    ipv6_enabled: bool = False

    # Block settings
    default_action: str = "DROP"
    reject_reason: str = "icmp-admin-prohibited"
    auto_block_enabled: bool = True
    auto_block_duration: int = 86400  # seconds

    # Logging
    log_level: str = "INFO"
    log_json: bool = True
    log_blocks: bool = True

    # Performance
    parallel_fetches: int = 3
    fetch_timeout: int = 30

    # Whitelist
    auto_whitelist_vpn: bool = True
    vpn_interfaces: List[str] = field(default_factory=lambda: ["tun0", "wg0", "proton0", "mullvad0"])

    # Active monitoring
    active_monitoring_enabled: bool = True
    nflog_group: int = 123
    scan_threshold_ports: int = 50
    scan_threshold_interval: int = 60
    ml_enabled: bool = False

    # Dashboard
    tui_enabled: bool = False
    web_enabled: bool = True
    web_port: int = 22355
    web_bind: str = "0.0.0.0"

    # Domain blocking
    domain_blocking_enabled: bool = True
    domain_feed_urls: List[str] = field(default_factory=list)
    max_domain_entries: int = 500000

    # Feed URLs (IP)
    feed_urls: List[str] = field(default_factory=list)

    # Runtime flags
    dry_run: bool = False

    def __post_init__(self) -> None:
        """Resolve paths to writable locations and create directories."""
        # Directories
        self.data_dir = _get_writable_path(self.data_dir, "MESHWALL_DATA_DIR",
                                           ".local/share/meshwall", is_dir=True)
        self.run_dir = _get_writable_path(self.run_dir, "MESHWALL_RUN_DIR",
                                          ".local/share/meshwall/run", is_dir=True)
        # Log file (is_file)
        system_log = Path("/var/log/meshwall/meshwall.log")
        self.log_file = _get_writable_path(system_log, "MESHWALL_LOG_FILE",
                                           ".cache/meshwall/meshwall.log", is_dir=False)
        # GeoIP
        if "MESHWALL_GEOIP_DB" in os.environ:
            self.geoip_db_path = Path(os.environ["MESHWALL_GEOIP_DB"])

        # Database path (file)
        db_default = Path("/var/lib/meshwall/meshwall.db")
        self.database_path = _get_writable_path(db_default, "MESHWALL_DATABASE",
                                                ".local/share/meshwall/meshwall.db", is_dir=False)

        # Feed defaults
        if not self.feed_urls:
            self.feed_urls = [
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "https://www.spamhaus.org/drop/drop.txt",
                "https://www.spamhaus.org/drop/edrop.txt",
            ]
        if not self.domain_feed_urls:
            self.domain_feed_urls = [
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
                "https://urlhaus.abuse.ch/downloads/hostfile/",
                "https://phishing.army/download/phishing_army_blocklist.txt",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
            ]


def load_config(path: Optional[Path] = None) -> Config:
    """Load configuration from file, with environment overrides."""
    if path is None:
        path = Path(os.getenv("MESHWALL_CONFIG", "/etc/meshwall/meshwall.conf"))

    cfg = Config()
    if path.exists():
        parser = configparser.ConfigParser()
        parser.read(path)

        # General
        if parser.has_section("DEFAULT"):
            cfg.update_frequency = parser.get("DEFAULT", "update_frequency", fallback=cfg.update_frequency)
            cfg.update_time = parser.get("DEFAULT", "update_time", fallback=cfg.update_time)
            cfg.max_entries = parser.getint("DEFAULT", "max_entries", fallback=cfg.max_entries)
            cfg.ipv6_enabled = parser.getboolean("DEFAULT", "ipv6_enabled", fallback=cfg.ipv6_enabled)

        # Block
        if parser.has_section("BLOCK"):
            cfg.default_action = parser.get("BLOCK", "default_action", fallback=cfg.default_action)
            cfg.reject_reason = parser.get("BLOCK", "reject_reason", fallback=cfg.reject_reason)
            cfg.auto_block_enabled = parser.getboolean("BLOCK", "auto_block_enabled", fallback=cfg.auto_block_enabled)
            cfg.auto_block_duration = parser.getint("BLOCK", "auto_block_duration", fallback=cfg.auto_block_duration)

        # Logging
        if parser.has_section("LOGGING"):
            cfg.log_file = Path(parser.get("LOGGING", "log_file", fallback=str(cfg.log_file)))
            cfg.log_level = parser.get("LOGGING", "log_level", fallback=cfg.log_level)
            cfg.log_json = parser.getboolean("LOGGING", "log_json", fallback=cfg.log_json)
            cfg.log_blocks = parser.getboolean("LOGGING", "log_blocks", fallback=cfg.log_blocks)

        # Performance
        if parser.has_section("PERFORMANCE"):
            cfg.parallel_fetches = parser.getint("PERFORMANCE", "parallel_fetches", fallback=cfg.parallel_fetches)
            cfg.fetch_timeout = parser.getint("PERFORMANCE", "fetch_timeout", fallback=cfg.fetch_timeout)

        # Whitelist
        if parser.has_section("WHITELIST"):
            cfg.auto_whitelist_vpn = parser.getboolean("WHITELIST", "auto_whitelist_vpn", fallback=cfg.auto_whitelist_vpn)
            ifaces = parser.get("WHITELIST", "vpn_interfaces", fallback="")
            if ifaces:
                cfg.vpn_interfaces = [i.strip() for i in ifaces.split(",")]

        # Active monitoring
        if parser.has_section("ACTIVE_MONITORING"):
            cfg.active_monitoring_enabled = parser.getboolean("ACTIVE_MONITORING", "enabled", fallback=cfg.active_monitoring_enabled)
            cfg.nflog_group = parser.getint("ACTIVE_MONITORING", "nflog_group", fallback=cfg.nflog_group)
            cfg.scan_threshold_ports = parser.getint("ACTIVE_MONITORING", "scan_threshold_ports", fallback=cfg.scan_threshold_ports)
            cfg.scan_threshold_interval = parser.getint("ACTIVE_MONITORING", "scan_threshold_interval", fallback=cfg.scan_threshold_interval)
            cfg.ml_enabled = parser.getboolean("ACTIVE_MONITORING", "ml_enabled", fallback=cfg.ml_enabled)
            if parser.has_option("ACTIVE_MONITORING", "ml_model_path"):
                cfg.ml_model_path = Path(parser.get("ACTIVE_MONITORING", "ml_model_path"))

        # Dashboard
        if parser.has_section("DASHBOARD"):
            cfg.tui_enabled = parser.getboolean("DASHBOARD", "tui_enabled", fallback=cfg.tui_enabled)
            cfg.web_enabled = parser.getboolean("DASHBOARD", "web_enabled", fallback=cfg.web_enabled)
            cfg.web_port = parser.getint("DASHBOARD", "web_port", fallback=cfg.web_port)
            cfg.web_bind = parser.get("DASHBOARD", "web_bind", fallback=cfg.web_bind)

        # Domain blocking
        if parser.has_section("DOMAIN_BLOCKING"):
            cfg.domain_blocking_enabled = parser.getboolean("DOMAIN_BLOCKING", "enabled", fallback=cfg.domain_blocking_enabled)
            cfg.dnsmasq_config = Path(parser.get("DOMAIN_BLOCKING", "dnsmasq_config", fallback=str(cfg.dnsmasq_config)))
            cfg.max_domain_entries = parser.getint("DOMAIN_BLOCKING", "max_domain_entries", fallback=cfg.max_domain_entries)
            feeds_str = parser.get("DOMAIN_BLOCKING", "feed_urls", fallback="")
            if feeds_str:
                cfg.domain_feed_urls = [url.strip() for url in feeds_str.split(",")]

    # Override with environment variables
    cfg.data_dir = Path(os.getenv("MESHWALL_DATA_DIR", cfg.data_dir))
    cfg.run_dir = Path(os.getenv("MESHWALL_RUN_DIR", cfg.run_dir))
    cfg.log_file = Path(os.getenv("MESHWALL_LOG_FILE", cfg.log_file))
    cfg.geoip_db_path = Path(os.getenv("MESHWALL_GEOIP_DB", cfg.geoip_db_path))
    cfg.database_path = Path(os.getenv("MESHWALL_DATABASE", cfg.database_path))
    cfg.log_level = os.getenv("MESHWALL_LOG_LEVEL", cfg.log_level).upper()

    # Ensure final paths are writable
    cfg.data_dir = _get_writable_path(cfg.data_dir, "MESHWALL_DATA_DIR", ".local/share/meshwall", is_dir=True)
    cfg.run_dir = _get_writable_path(cfg.run_dir, "MESHWALL_RUN_DIR", ".local/share/meshwall/run", is_dir=True)
    cfg.log_file = _get_writable_path(cfg.log_file, "MESHWALL_LOG_FILE", ".cache/meshwall/meshwall.log", is_dir=False)
    cfg.database_path = _get_writable_path(cfg.database_path, "MESHWALL_DATABASE", ".local/share/meshwall/meshwall.db", is_dir=False)

    return cfg