# MeshWall Technical Documentation

## Version 3.0 – Adaptive Firewall Augmentation

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Command-Line Interface](#command-line-interface)
6. [Core Modules](#core-modules)
7. [Web Dashboard](#web-dashboard)
8. [AI Integration (Ollama)](#ai-integration-ollama)
9. [Domain Blocking with dnsmasq](#domain-blocking-with-dnsmasq)
10. [Systemd Services](#systemd-services)
11. [Database Schema](#database-schema)
12. [Performance and Security](#performance-and-security)
13. [Troubleshooting](#troubleshooting)
14. [Development Guide](#development-guide)
15. [License](#license)

---

## Introduction

MeshWall is a lightweight, autonomous firewall augmentation tool that dynamically blocks malicious network traffic at the kernel level. It retrieves threat intelligence from public IP and domain blocklists, actively monitors all TCP/UDP ports for scanning activity using packet capture, and provides optional AI-powered analysis via local large language models. MeshWall operates completely offline; no telemetry or external data leaves the host.

Key capabilities:

-   Automated fetching and merging of IP blocklists from Firehol, Spamhaus, Feodo Tracker, and others.
-   Kernel-level blocking via `ipset` and `iptables`, supporting hundreds of thousands of entries with O(1) lookups.
-   Real-time port scan detection using scapy, with automatic insertion of detected scanners into the blocklist.
-   DNS sinkhole through `dnsmasq` for domain-based blocking of telemetry, tracking, and malicious sites.
-   Web dashboard for monitoring blocked IPs, attack map, domain checker, and AI chat.
-   Offline IP geolocation and traceroute for identified attackers.
-   Encrypted AI chat history with RAG-based context from past scan events.

MeshWall is designed to run on low-power devices such as Raspberry Pi 5, Mini PCs, and standard Linux laptops.

---

## Architecture Overview

MeshWall consists of several independent components that interact via a shared SQLite database and the operating system’s firewall subsystems.

```
┌──────────────────────────────────────────────┐
│                  CLI (meshwall)              │
│  update | domain-update | listen | web | ... │
└──────┬───────────┬───────────┬──────────────┘
       │           │           │
       ▼           ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│  fetcher  │ │ domain   │ │   listener   │
│ (IP feeds)│ │ fetcher  │ │ (scapy snif) │
└────┬─────┘ └────┬─────┘ └──────┬───────┘
     │            │              │
     ▼            ▼              ▼
┌─────────────┐ ┌─────────────┐ ┌──────────────┐
│ ipset/iptab │ │  dnsmasq    │ │   database   │
│ (kernel)    │ │ (DNS sink)  │ │ (SQLite)     │
└─────────────┘ └─────────────┘ └──────┬───────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │   Web Dashboard │
                              │   (Flask)        │
                              └─────────────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │  AI (Ollama)    │
                              └─────────────────┘
```

- **fetcher.py**: Downloads IP blocklists, deduplicates them, and loads them into an `ipset` set. A corresponding `iptables` rule drops traffic from these IPs.
- **domain_fetcher.py**: Downloads domain blocklists (hosts file format) and writes a `dnsmasq` configuration that sinks requests for those domains.
- **listener.py**: Uses scapy to capture TCP SYN and UDP packets, aggregates connections per source IP, and triggers an alert when a scan threshold is exceeded. Detected IPs are added to the `ipset` set and recorded in the database for the dashboard.
- **trace.py**: Performs offline geolocation using a MaxMind GeoLite2 database and a `traceroute` to the attacker.
- **ai/**: Provides an asynchronous client for Ollama, a RAG index over saved trace files, and a summarizer that generates natural language reports.
- **webapp/**: Flask application with blueprints for dashboard, domain checker, and AI chat. All assets (Leaflet, CSS, map tiles) are served locally; no external resources are required.
- **db.py / models.py**: SQLAlchemy setup with shared models (`BlockedIP`, `BlockedDomain`, `ChatMessage`, `FeedBlock`). Used by both the CLI tools and the web app.

---

## Installation

### Prerequisites

- Linux kernel with `ipset` and `iptables` (or `nftables` compatibility layer)
- Python 3.10 or higher
- `dnsmasq` (for domain blocking)
- `traceroute` (typically part of the `inetutils` package)
- `scapy` requires root privileges or `CAP_NET_RAW` capability
- Optional: [Ollama](https://ollama.ai) for AI features

### System Dependencies

```bash
sudo apt update
sudo apt install ipset iptables dnsmasq traceroute   # Debian/Ubuntu
sudo dnf install ipset iptables dnsmasq traceroute    # Fedora
```

### Python Virtual Environment (Recommended)

```bash
git clone https://github.com/nyakki-labs/meshwall.git
cd meshwall
python -m venv venv
source venv/bin/activate
pip install -e .
```

For AI functionality, install the additional dependencies:

```bash
pip install -e ".[ai]"
```

### Configuration File (Optional)

A default configuration is built into the application. To override settings, create `/etc/meshwall/meshwall.conf`:

```bash
sudo mkdir -p /etc/meshwall
sudo cp meshwall.conf.example /etc/meshwall/meshwall.conf
```

### Initial Database Setup

Before starting the web dashboard, create the database tables:

```bash
meshwall init-db
```

---

## Configuration

MeshWall reads settings from the configuration file `/etc/meshwall/meshwall.conf`. The file uses standard INI format. All options have sensible defaults.

### Example Configuration

```ini
[DEFAULT]
update_frequency = daily
update_time = 03:00
max_entries = 200000
ipv6_enabled = false

[BLOCK]
default_action = DROP
auto_block_enabled = true
auto_block_duration = 86400

[LOGGING]
log_file = /var/log/meshwall/meshwall.log
log_level = INFO
log_json = true

[PERFORMANCE]
parallel_fetches = 3
fetch_timeout = 30

[WHITELIST]
auto_whitelist_vpn = true
vpn_interfaces = tun0, wg0

[ACTIVE_MONITORING]
enabled = true
nflog_group = 123
scan_threshold_ports = 50
scan_threshold_interval = 60
ml_enabled = false

[DOMAIN_BLOCKING]
enabled = true
dnsmasq_config = /etc/dnsmasq.d/meshwall-block.conf
max_domain_entries = 500000
feed_urls = https://urlhaus.abuse.ch/downloads/hostfile/,https://phishing.army/download/phishing_army_blocklist.txt

[DASHBOARD]
web_enabled = true
web_port = 22355
web_bind = 0.0.0.0
```

### Section Reference

- **DEFAULT**: General update scheduling and limits.
- **BLOCK**: Behavior of iptables rules (DROP/REJECT), automatic block duration for detected scanners.
- **LOGGING**: Log file path, level, and format (JSON or console).
- **PERFORMANCE**: Number of parallel feed fetches and timeout.
- **WHITELIST**: VPN interfaces whose addresses are automatically whitelisted.
- **ACTIVE_MONITORING**: Enable/disable port monitoring, scan detection thresholds, and (future) ML model path.
- **DOMAIN_BLOCKING**: Enable/disable DNS sinkhole, location of dnsmasq config, maximum domains, and custom feed URLs.
- **DASHBOARD**: Web interface port and bind address.

Environment variables can override individual settings. The most common:

- `MESHWALL_CONFIG` – path to the configuration file.
- `MESHWALL_DATA_DIR` – directory for runtime data (default: `/var/lib/meshwall` or `~/.local/share/meshwall`).
- `MESHWALL_LOG_FILE` – path to log file.
- `MESHWALL_DATABASE` – path to SQLite database file.
- `MESHWALL_ENCRYPTION_KEY` – passphrase for encrypting chat history.
- `MESHWALL_SALT` – fixed salt for Argon2id key derivation.

---

## Command-Line Interface

All commands are accessed via the `meshwall` entry point.

```
Usage: meshwall [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config TEXT  Path to config file.
  --debug            Enable debug logging.
  --help             Show this message and exit.

Commands:
  update           Fetch and apply IP blocklists.
  domain-update    Fetch and apply domain blocklist.
  status           Show active ipsets and iptables rules.
  listen           Start real-time scan detector (requires root).
  web              Start the web dashboard.
  init-db          Create missing database tables.
  whitelist        Manage IP whitelist.
  trace            Geolocate and traceroute an IP.
  log              View structured logs.
  stats            Summary of blocked attempts.
  summarize        AI summary of recent activity (requires Ollama).
  ask              Ask AI about past events.
  test             Test connectivity to threat feeds.
  diag             Diagnose ipset/iptables setup.
```

### Detailed Command Reference

#### `meshwall update`

Fetches IP blocklists from the configured feeds and loads them into the `meshwall-block` ipset. Also writes all feed IPs into the `feed_block` database table for the dashboard.

```bash
sudo meshwall update
```

Options:
- `--verbose`, `-v`: Show detailed fetch progress.
- `--dry-run`: Parse feeds but do not modify ipset/iptables.
- `--with-domains`: Also run domain feed update in the same invocation.

#### `meshwall domain-update`

Fetches domain blocklists and writes a `dnsmasq` configuration file. Reloads `dnsmasq` automatically.

```bash
sudo meshwall domain-update
```

#### `meshwall status`

Displays the current state of ipsets and the number of active iptables rules.

```bash
meshwall status
```

Note: For ipset information, this command should be run with `sudo` unless the system path is writable.

#### `meshwall listen`

Starts the active port scan detector. Requires root privileges. The listener runs in the foreground; use systemd for a persistent service.

```bash
sudo meshwall listen
```

#### `meshwall web`

Launches the Flask web dashboard on the configured port (default: 22355).

```bash
meshwall web
```

Options:
- `--host`: Bind address (default from config or `0.0.0.0`)
- `--port`: Port number (default from config or `22355`)

#### `meshwall init-db`

Creates any missing database tables. Safe to run multiple times.

```bash
meshwall init-db
```

#### `meshwall whitelist`

Manage permanent IP whitelist entries.

```bash
meshwall whitelist add 192.168.1.0/24
meshwall whitelist remove 10.0.0.5
meshwall whitelist list
```

#### `meshwall trace`

Performs geolocation and traceroute on an IP address.

```bash
meshwall trace 45.155.205.233
```

#### `meshwall log`

Views the MeshWall log file.

```bash
meshwall log            # Show entire log
meshwall log --tail     # Follow the log (like tail -f)
```

#### `meshwall stats`

Prints the total count of currently blocked IPs.

#### `meshwall summarize`

Asks the configured Ollama model to summarize scan events from the last N hours (default 24).

```bash
meshwall summarize --hours 48
```

#### `meshwall ask`

Queries the AI about historical scan events using RAG over saved traces.

```bash
meshwall ask "Which countries scanned me this week?"
```

#### `meshwall test`

Checks connectivity to each configured IP feed and reports HTTP status and response time.

#### `meshwall diag`

Runs diagnostics: verifies ipset/iptables availability, writability of data directory, and ability to create a test ipset. Must be run with `sudo` for complete results.

---

## Core Modules

### `fetcher.py` – IP Feed Updater

The `FeedUpdater` class downloads blocklists, parses CIDR notation, deduplicates entries, and applies them using `ipset` and `iptables`. It also stores feed IPs in the `feed_block` database table for the web dashboard.

### `domain_fetcher.py` – Domain Feed Updater

Downloads hosts-format blocklists, extracts domain names, and generates a `dnsmasq` configuration using `address=/domain/0.0.0.0` directives. Reloads `dnsmasq` after writing.

### `ipset_manager.py`

Manages ipset sets: creation, atomic swap, listing, and individual IP addition/removal.

### `iptables_manager.py`

Creates the `MESHWALL` chain, inserts the jump rule, and adds the ipset matching rule.

### `listener.py`

Uses scapy to sniff TCP SYN and UDP packets. The `ScanDetector` class maintains a sliding window of connections per source IP and raises an alert when the number of distinct ports exceeds the configured threshold. Detected scanners are immediately traced, inserted into the database, and optionally added to the ipset blocklist.

### `trace.py`

Provides offline geolocation (using MaxMind GeoLite2-City) and asynchronous traceroute. Results are saved as JSON in the `traces/` directory.

### `ai/`

- `client.py`: Async HTTP client for Ollama’s API (`/api/generate` and `/api/chat`).
- `rag.py`: In-memory keyword-based index over saved trace files.
- `summarizer.py`: Orchestrates data gathering (traces, logs, ipset stats) and uses the RAG index to answer questions or generate summaries.

### `db.py`

Shared SQLAlchemy engine and session factory. The database URI is determined by the `MESHWALL_DATABASE` environment variable or the `database_path` configuration option.

### `models.py`

SQLAlchemy ORM models:

- `BlockedIP`: IPs detected by the listener.
- `BlockedDomain`: Domains blocked via domain checker.
- `ChatMessage`: Encrypted AI chat messages.
- `FeedBlock`: IPs loaded from threat feeds.

---

## Web Dashboard

The dashboard is a Flask application composed of three blueprints.

### Blueprints

- **dashboard** (`/`): Displays total blocked IPs (from `feed_block`), a table of recently detected attacker IPs, and an attack map. The map uses an offline canvas tile layer; no external tile servers are needed.
- **domains** (`/domains`): Allows users to submit a domain for passive analysis. Checks DNS, TLS, CNAME, typosquat similarity, and a keyword blocklist. If the domain fails any check, it is automatically added to the `blocked_domain` table.
- **chat** (`/chat`): Chat interface to the Ollama model. Conversation history is encrypted using AES-256-GCM with a key derived from `MESHWALL_ENCRYPTION_KEY` and a fixed salt via Argon2id.

### Static Assets

All JavaScript and CSS are served locally. Leaflet is placed in `static/js/leaflet.js` and `static/css/leaflet.css`. The offline tile layer is defined in `static/js/offline-tiles.js`. No internet connection is required for the frontend.

### Templates

Jinja2 templates extend a `base.html` that defines the navigation bar and imports. The green-black theme is applied via `static/css/style.css`.

---

## AI Integration (Ollama)

### Setup

1. Install Ollama from [ollama.ai](https://ollama.ai) or via package manager.
2. Start the Ollama service: `systemctl start ollama` or `ollama serve`.
3. Pull a model: `ollama pull phi3:mini`.

### Usage

The CLI commands `meshwall summarize` and `meshwall ask` communicate with Ollama directly. The web dashboard chat interface also uses the same backend. MeshWall does not pull the model automatically; this must be done manually as shown above.

### Encryption

All chat messages stored in the database are encrypted with AES-256-GCM. The encryption key is derived from the `MESHWALL_ENCRYPTION_KEY` environment variable using Argon2id with a static salt (configurable via `MESHWALL_SALT`). If the key is lost, the chat history cannot be recovered.

---

## Domain Blocking with dnsmasq

MeshWall acts as a DNS sinkhole by feeding a blocklist to `dnsmasq`. When a client on the network queries a blocked domain, `dnsmasq` returns `0.0.0.0` (or the IPv6 equivalent), effectively null-routing the request.

### Configuration Steps

1. Install `dnsmasq`.
2. Configure `dnsmasq` to serve the system:

```
interface=lo
bind-interfaces
no-resolv
server=9.9.9.9
server=149.112.112.112
conf-dir=/etc/dnsmasq.d/,*.conf
```

3. Set the system’s DNS resolver to `127.0.0.1` (via `/etc/resolv.conf` or NetworkManager).
4. Run `sudo meshwall domain-update` to populate the blocklist.
5. Enable the systemd timer for automatic updates (see below).

---

## Systemd Services

Four service units are provided in the `scripts/` directory.

### `meshwall-fetch.service` / `.timer`

Daily IP feed update. Enable with:

```bash
sudo systemctl enable --now meshwall-fetch.timer
```

### `meshwall-listener.service`

Persistent packet sniffing service. Enable with:

```bash
sudo systemctl enable --now meshwall-listener
```

### `meshwall-domain-update.service` / `.timer`

Daily domain feed update. Enable with:

```bash
sudo systemctl enable --now meshwall-domain-update.timer
```

### `meshwall-monitor.service`

Runs the web dashboard. Enable with:

```bash
sudo systemctl enable --now meshwall-monitor
```

All services use the absolute path to the Python interpreter inside the virtual environment. Adjust `ExecStart` if your venv location differs.

---

## Database Schema

The SQLite database is stored at the path defined by `database_path` (or `MESHWALL_DATABASE`). The following tables exist:

**blocked_ip**

| Column       | Type     | Description                               |
|--------------|----------|-------------------------------------------|
| id           | INTEGER  | Primary key                               |
| ip           | VARCHAR  | Source IP                                 |
| reason       | VARCHAR  | Detection trigger                         |
| geo_country  | VARCHAR  | ISO country code                          |
| geo_city     | VARCHAR  | City name                                 |
| asn          | VARCHAR  | Autonomous system number                  |
| provider     | VARCHAR  | ISP/Organization                          |
| lat          | FLOAT    | Latitude                                  |
| lng          | FLOAT    | Longitude                                 |
| traceroute   | TEXT     | JSON list of hops                         |
| blocked_at   | DATETIME | Timestamp of detection                    |

**blocked_domain**

| Column       | Type     | Description                               |
|--------------|----------|-------------------------------------------|
| id           | INTEGER  | Primary key                               |
| domain       | VARCHAR  | Blocked domain                            |
| reason       | VARCHAR  | Reason for blocking                       |
| blocked_at   | DATETIME | Timestamp                                 |

**chat_message**

| Column            | Type     | Description                               |
|-------------------|----------|-------------------------------------------|
| id                | INTEGER  | Primary key                               |
| role              | VARCHAR  | `user` or `assistant`                     |
| content_encrypted | TEXT     | AES-256-GCM ciphertext                   |
| created_at        | DATETIME | Timestamp                                 |

**feed_block**

| Column    | Type     | Description                               |
|-----------|----------|-------------------------------------------|
| id        | INTEGER  | Primary key                               |
| ip        | VARCHAR  | IP from feed                              |
| source    | VARCHAR  | Feed identifier                           |
| added_at  | DATETIME | Timestamp                                 |

---

## Performance and Security

### Resource Usage

- ipset lookup is O(1); even with 100,000 entries, the impact on packet processing is negligible.
- The listener uses a sliding window and only stores connection metadata for the configured interval, limiting memory usage.
- The web dashboard serves static assets from disk; the map uses a lightweight canvas tile layer to avoid heavy I/O.

### Hardening

- All commands that modify network state require root privileges; the web app runs as a separate, unprivileged user.
- The systemd services drop unnecessary capabilities and use `ProtectSystem=strict` with explicit `ReadWritePaths`.
- AI chat encryption uses industry-standard AES-256-GCM and Argon2id; the passphrase is never stored in plain text within the codebase.

---

## Troubleshooting

### `meshwall web` shows a 500 error

Check the terminal output for a Python traceback. Most often, the database tables are missing. Run:

```bash
meshwall init-db
```

### Dashboard shows 0 blocked IPs

Run `sudo meshwall update` to populate the `feed_block` table. If the listener has not detected any scans, the map and recent IPs table will be empty; this is normal.

### Map not loading

Verify that the static files `leaflet.js`, `leaflet.css`, and `offline-tiles.js` exist in `src/meshwall/webapp/static/`. If they are missing, download them from the Leaflet website and create the offline tile script as described in the project repository.

### Listener service failing

Check `sudo journalctl -u meshwall-listener -n 20`. Common issues:

- Wrong path to Python interpreter in `ExecStart`. Update the service file with the correct path.
- `No module named meshwall`: Reinstall the package with `pip install -e .` inside the venv.
- `PermissionError`: Ensure the user has `CAP_NET_RAW` capability or runs as root.

### AI features not working

- Verify Ollama is running: `curl http://localhost:11434/api/tags`
- Ensure the model is pulled: `ollama pull phi3:mini`
- Confirm `httpx` is installed: `pip install httpx`

### Domain checker not blocking

The domain checker uses the `blocked_domain` table. Populate it with `sudo meshwall domain-update` and run the checker via the web UI.

---

## Development Guide

MeshWall uses an editable pip install (`pip install -e .`). After making changes to the source code, restart the affected service or the web dashboard.

### Project Layout

```
meshwall/
├── src/meshwall/          # Main package
│   ├── cli.py             # Click CLI
│   ├── config.py          # Configuration
│   ├── fetcher.py         # IP feed updater
│   ├── domain_fetcher.py  # Domain feed updater
│   ├── ipset_manager.py   # ipset wrapper
│   ├── iptables_manager.py# iptables wrapper
│   ├── listener.py        # Packet sniffer
│   ├── trace.py           # Geolocation/traceroute
│   ├── utils.py           # Logging
│   ├── models.py          # SQLAlchemy models
│   ├── db.py              # Database engine/session
│   ├── ai/                # AI client, RAG, summarizer
│   └── webapp/            # Flask web dashboard
│       ├── app.py         # App factory
│       ├── extensions.py  # SQLAlchemy init, encryption
│       ├── domain_checker.py # Passive domain checks
│       ├── blueprints/    # Flask blueprints
│       ├── templates/     # Jinja2 templates
│       └── static/        # CSS, JS, images
├── scripts/               # systemd unit files
├── pyproject.toml         # Build metadata and dependencies
├── .env.example           # Environment variable examples
├── LICENSE                # GPLv3
└── README.md
```

### Running Tests

A basic test suite can be run with pytest (if installed):

```bash
pip install -e ".[dev]"
pytest
```

```markdown
## Running Tests

MeshWall includes a test suite using `pytest`. The tests are located in the `tests/` directory (create it if it does not exist). The following instructions assume you have installed MeshWall in development mode with the `dev` extra:

```bash
pip install -e ".[dev]"
```

### Running the Full Suite

To execute all tests, run the following command from the project root:

```bash
pytest
```

`pytest` automatically discovers files matching `test_*.py` or `*_test.py` under the `tests/` folder.

### Running a Specific Test Module

To run a single test file:

```bash
pytest tests/test_fetcher.py
```

### Running with Verbose Output

For detailed output, including test names and pass/fail status:

```bash
pytest -v
```

### Running with Coverage

If you have installed `pytest-cov` (included in the `dev` extra), generate a coverage report:

```bash
pytest --cov=meshwall --cov-report=term-missing
```

This shows which lines of code were executed during the tests and highlights any missing coverage.

### Writing Tests

Tests should be placed in the `tests/` directory, mirroring the structure of `src/meshwall/`. For example:

```
tests/
├── test_fetcher.py
├── test_listener.py
├── test_ipset_manager.py
├── test_webapp/
│   ├── test_dashboard.py
│   └── test_domains.py
└── conftest.py          # shared fixtures
```

A minimal test using `pytest` and temporary files:

```python
# tests/test_fetcher.py
import pytest
from meshwall.fetcher import FeedUpdater
from meshwall.config import Config

def test_parse_feed():
    config = Config()
    updater = FeedUpdater(config)
    # Mock a feed response or use a local file
    ...
```

### Fixtures and Mocking

Use `pytest` fixtures to set up temporary databases, mock network calls, or override configuration:

```python
# tests/conftest.py
import pytest
from meshwall.config import Config

@pytest.fixture
def test_config(tmp_path):
    """Create a temporary configuration for testing."""
    config = Config()
    config.data_dir = tmp_path / "data"
    config.run_dir = tmp_path / "run"
    config.log_file = tmp_path / "test.log"
    return config
```

### Testing CLI Commands

You can test CLI commands using `click.testing.CliRunner`:

```python
from click.testing import CliRunner
from meshwall.cli import cli

def test_status_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['status'])
    assert result.exit_code == 0
    assert 'MeshWall Status' in result.output
```

### Isolating Network Calls

For unit tests, avoid real network requests. Use `aioresponses` or `unittest.mock` to simulate HTTP responses when testing `fetcher.py` or `domain_fetcher.py`.

### Test Database

The test suite uses an in‑memory SQLite database or a temporary file to avoid affecting the production database. This is typically configured in the `conftest.py` by setting `DATABASE_URL=sqlite:///:memory:` before importing `db.py`.

```python
import os
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
from meshwall.db import init_db
```


---

## License

MeshWall is licensed under the GNU General Public License v3.0 or later. See the `LICENSE` file for the full text.