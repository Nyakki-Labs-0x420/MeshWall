# MeshWall – Adaptive Firewall Augmentation

**Version 1.0**

MeshWall is a lightweight, autonomous firewall augmentation tool that
dynamically blocks malicious traffic at the kernel level. It fetches threat
intelligence from public IP and domain blocklists, actively monitors network
ports for scanning activity, and provides an optional local AI assistant for
analysis. MeshWall operates entirely offline; no telemetry or data leaves the
host.

## Features

- **Threat Intelligence Feeds** – Automatically fetches and merges IP blocklists
  from Firehol, Spamhaus, Feodo Tracker, and others.
- **Kernel‑Level Blocking** – Uses `ipset` and `iptables` for O(1) lookups even
  with hundreds of thousands of entries.
- **Active Port Monitoring** – Listens on all TCP/UDP ports without opening
  65 k sockets. Uses the kernel’s NFLOG facility to deliver only relevant
  packets, avoiding the overhead of a full Python packet‑capture loop.
- **AI‑Powered Assistant** – Optional integration with a local Ollama model to
  answer questions about blocked IPs, recent scans, and attacker geolocation.
  Chat history is encrypted with AES‑256‑GCM and Argon2id.
- **DNS Sinkhole** – Blocks telemetry, tracking, and malicious domains
  network‑wide via `dnsmasq`.
- **Offline IP Geolocation and Traceroute** – Traces and geolocates attackers
  using a local MaxMind GeoLite2 database.
- **Web Dashboard** – A self‑hosted Flask application with a green/black theme,
  offline map, domain checker, and AI chat. Serves all assets locally.
- **Zero‑Trust, Zero‑Telemetry** – No data ever leaves the system.
- **Set‑and‑Forget** – Runs as background services via systemd timers and units.
- **Lightweight** – Tested on Raspberry Pi 5, Mini PCs, and standard Linux
  laptops.

## Project Structure

```
meshwall/
├── src/
│   └── meshwall/
│       ├── cli.py                # Command-line interface
│       ├── config.py             # Configuration management
│       ├── fetcher.py            # IP feed fetcher and parser
│       ├── domain_fetcher.py     # Domain feed fetcher (DNS sinkhole)
│       ├── ipset_manager.py      # ipset operations
│       ├── iptables_manager.py   # iptables rule management
│       ├── listener_nflog.py     # NFLOG‑based active scan detection
│       ├── listener.py           # Legacy scapy listener (optional)
│       ├── trace.py              # GeoIP and traceroute
│       ├── utils.py              # Logging and helpers
│       ├── models.py             # Shared SQLAlchemy models
│       ├── db.py                 # Database session manager
│       ├── ai/                   # AI client, RAG, summarizer
│       └── webapp/               # Flask web dashboard
│           ├── app.py
│           ├── extensions.py
│           ├── domain_checker.py
│           ├── blueprints/
│           ├── templates/
│           └── static/
├── scripts/                      # systemd unit files
├── pyproject.toml
├── .env.example
├── LICENSE                       # GPLv3
└── README.md
```

## Quick Start

### Prerequisites

- Linux with Python 3.10 or higher
- `ipset` and `iptables`
- `dnsmasq` (for domain blocking)
- `traceroute` (usually in `inetutils`)
- Optional: [Ollama](https://ollama.ai) for AI features

### Installation

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

### Basic Setup

1.  Create the configuration file (optional – sensible defaults are used):
    ```bash
    sudo mkdir -p /etc/meshwall
    sudo cp meshwall.conf.example /etc/meshwall/meshwall.conf
    ```

2.  Initialise the database:
    ```bash
    meshwall init-db
    ```

3.  Test connectivity to threat feeds:
    ```bash
    meshwall test
    ```

4.  Perform an initial IP blocklist update:
    ```bash
    sudo meshwall update
    ```

5.  Start the web dashboard:
    ```bash
    meshwall web
    ```
    Open `http://127.0.0.1:22355` in your browser.

6.  (Optional) Start the active listener:
    ```bash
    sudo meshwall listen
    ```

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

## Configuration

MeshWall reads settings from `/etc/meshwall/meshwall.conf`. The file uses
standard INI format. All options have sensible defaults.

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
scan_threshold_ports = 50
scan_threshold_interval = 60

[DOMAIN_BLOCKING]
enabled = true
dnsmasq_config = /etc/dnsmasq.d/meshwall-block.conf
max_domain_entries = 500000

[DASHBOARD]
web_enabled = true
web_port = 22355
web_bind = 0.0.0.0
```

Environment variables can override individual settings:

- `MESHWALL_CONFIG` – path to the configuration file.
- `MESHWALL_DATA_DIR` – directory for runtime data.
- `MESHWALL_LOG_FILE` – path to log file.
- `MESHWALL_DATABASE` – path to SQLite database file.
- `MESHWALL_ENCRYPTION_KEY` – passphrase for encrypting chat history.
- `MESHWALL_SALT` – fixed salt for Argon2id key derivation.

## Active Port Monitoring

The active listener uses the kernel’s NFLOG facility to deliver only TCP SYN
and UDP NEW packets. It does not open 65 k sockets. Packet parsing is limited
to IP/TCP/UDP headers, so the listener remains lightweight even during rapid
port scans.

The listener automatically adds and removes the necessary iptables rules when
it starts and stops. No manual iptables configuration is required.

If you prefer to use the original scapy‑based listener, you can modify the
`listen` command in `cli.py` to import `ListenerDaemon` from `listener.py`
instead of the default NFLOG listener.

## AI Integration (Ollama)

MeshWall can use a local Ollama instance to answer questions about your
firewall data. The web dashboard includes a chat interface that communicates
with an uncensored model. The assistant has access to live data: total blocked
IPs, recent scan events, top attacking countries, and individual attacker
geolocation.

All inference runs locally. No data is sent outside the machine.

### Setup

1.  Install Ollama from [ollama.ai](https://ollama.ai).
2.  Start the Ollama service and pull the recommended model:
    ```bash
    ollama pull artifish/llama3.2-uncensored:latest
    ```
3.  Install MeshWall with AI extras:
    ```bash
    pip install -e ".[ai]"
    ```

### Model choice

The default model is `artifish/llama3.2-uncensored:latest` (3.6B parameters,
~2.2 GB). It runs comfortably on a Raspberry Pi 5, Mini PC, or any laptop with
8 GB RAM.

To change the model, edit the `MODEL` variable in
`meshwall/webapp/blueprints/ai_chat.py`. Other small uncensored models include:

- `tinyllama:latest` (lightest, ~637 MB)
- `dolphin3.0-mistral-7b:q4_K_M`
- `hermes3:8b-llama3.1-q4_K_M`
- `qwen2.5-coder:7b-instruct-q4_K_M`

### Encryption

Chat messages stored in the database are encrypted with AES‑256‑GCM. The
encryption key is derived from the `MESHWALL_ENCRYPTION_KEY` environment
variable using Argon2id with a configurable salt.

## Domain Blocking with dnsmasq

MeshWall acts as a DNS sinkhole by feeding a blocklist to `dnsmasq`. When a
client queries a blocked domain, `dnsmasq` returns `0.0.0.0`, null‑routing the
request.

1.  Install and configure `dnsmasq`:
    ```
    interface=lo
    bind-interfaces
    no-resolv
    server=9.9.9.9
    server=149.112.112.112
    conf-dir=/etc/dnsmasq.d/,*.conf
    ```
2.  Point your system’s DNS resolver to `127.0.0.1`.
3.  Run `sudo meshwall domain-update`.
4.  Enable the systemd timer for automatic updates:
    ```bash
    sudo systemctl enable --now meshwall-domain-update.timer
    ```

## Systemd Services

Four service units are provided in `scripts/`.

- `meshwall-fetch.timer` / `.service` – Daily IP feed update.
- `meshwall-listener.service` – Persistent packet sniffing service.
- `meshwall-domain-update.timer` / `.service` – Daily domain feed update.
- `meshwall-monitor.service` – Runs the web dashboard.

Enable them with:

```bash
sudo cp scripts/*.service scripts/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now meshwall-fetch.timer
sudo systemctl enable --now meshwall-listener
sudo systemctl enable --now meshwall-domain-update.timer
sudo systemctl enable --now meshwall-monitor
```

## Troubleshooting

- **Dashboard shows 0 blocked IPs** – Run `sudo meshwall update` to populate
  the database, then refresh.
- **Map not loading** – Verify that `leaflet.js`, `leaflet.css`, and
  `offline-tiles.js` exist in `src/meshwall/webapp/static/`.
- **Listener service fails** – Check the journal:
  ```bash
  sudo journalctl -u meshwall-listener -n 20 --no-pager
  ```
  Ensure the Python path in the service file is correct and the package is
  installed.
- **AI features not working** – Verify Ollama is running (`curl
  http://localhost:11434/api/tags`) and the model is pulled (`ollama list`).
- **Database errors** – Run `meshwall init-db` to create missing tables.

## License

MeshWall is licensed under the GNU General Public License v3.0 or later. See
the `LICENSE` file for the full text.
