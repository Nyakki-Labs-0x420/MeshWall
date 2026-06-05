"""Utility functions."""

import logging
from pathlib import Path
from typing import Optional

import structlog
from rich.console import Console
from rich.logging import RichHandler


def setup_logging(level: str = "INFO", log_file: Optional[Path] = None, json_format: bool = False, debug: bool = False) -> None:
    """Configure structured logging with beautiful console output."""
    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)

    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
    console_level = logging.DEBUG if debug else logging.WARNING
    file_level = logging.DEBUG if debug else getattr(logging, level.upper(), logging.INFO)

    handlers = []
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(file_level)
        file_formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer() if json_format else structlog.dev.ConsoleRenderer(colors=False),
            foreign_pre_chain=[structlog.stdlib.add_log_level, timestamper],
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    console_handler = RichHandler(console=Console(stderr=True), rich_tracebacks=True, show_time=False)
    console_handler.setLevel(console_level)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
        foreign_pre_chain=[structlog.stdlib.add_log_level, timestamper],
    )
    console_handler.setFormatter(console_formatter)
    handlers.append(console_handler)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer(colors=True) if not json_format else structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def validate_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_network(net: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False