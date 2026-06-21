#  MeshWall – Adaptive Firewall Augmentation

**Version 1.0 (Active Monitoring & AI Edition)**  
MeshWall is a lightweight, autonomous firewall augmentation tool that **dynamically blocks malicious traffic** at the network layer. It pulls threat intelligence from public feeds, **actively monitors every port** for suspicious connection attempts, uses **local AI to summarise attack patterns**, and can sinkhole telemetry & malware domains via DNS.

Everything runs **offline** – no telemetry, no phoning home, no cloud dependency.

---

## Features

- **Threat Intelligence Feeds** – Automatically fetches and merges IP blocklists from Firehol, Spamhaus, Feodo Tracker, and more.
- **Atomic ipset + iptables** – Kernel‑level blocking with O(1) lookups, even with 100k+ entries.
- **Active Port Monitoring** – Listens on all TCP/UDP ports (without opening 65k sockets) and **detects port scans in real‑time** using rule‑based heuristics.
- **AI‑Powered Summaries** – Optional integration with [Ollama](https://ollama.ai) to generate human‑readable security reports and answer questions about past attacks (RAG).
- **DNS Sinkhole** – Blocks telemetry, tracking, and malicious domains network‑wide via `dnsmasq`.
- **Offline IP Geolocation & Traceroute** – When a scan is detected, MeshWall traces the attacker’s network path and geolocates the source using a local MaxMind database.
- **Web Dashboard** – Green/black cyberpunk dashboard showing blocked IPs, attack map, domain blocker, and AI chat. Fully self‑hosted, no external assets.
- **Zero‑Trust, Zero‑Telemetry** – All data stays on your machine. No cloud, no accounts, no hidden analytics.
- **Set‑and‑Forget** – Runs silently via systemd timers and services.
- **Lightweight** – Runs comfortably on a Raspberry Pi 5, a MiniPC, or any Linux laptop.

---

## Project Structure

```
meshwall/
├── src/
│   └── meshwall/
│       ├── cli.py                # Command-line interface
│       ├── config.py             # Configuration management
│       ├── fetcher.py            # IP feed fetcher & parser
│       ├── domain_fetcher.py     # Domain feed fetcher (DNS sinkhole)
│       ├── ipset_manager.py      # ipset operations
│       ├── iptables_manager.py   # iptables rule management
│       ├── listener.py           # Active scan detection (scapy)
│       ├── trace.py              # GeoIP & traceroute
│       ├── utils.py              # Logging & helpers
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
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Quick Start

### Prerequisites

- Linux with Python ≥ 3.10
- `ipset` and `iptables` (usually pre‑installed)
- `dnsmasq` (for domain blocking)
- `scapy` requires root / `CAP_NET_RAW`
- (Optional) [Ollama](https://ollama.ai) for AI features

### Installation

```bash
# Clone the repository
git clone https://github.com/nyakki-labs/meshwall.git
cd meshwall

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate

# Install MeshWall with all extras
pip install -e ".[ai]"
```

### Basic Setup

1. **Create the configuration file** (optional – sensible defaults are used):
   ```bash
   sudo mkdir -p /etc/meshwall
   sudo cp meshwall.conf.example /etc/meshwall/meshwall.conf
   ```

2. **Test connectivity to threat feeds**:
   ```bash
   meshwall test
   ```

3. **Perform an initial IP blocklist update**:
   ```bash
   sudo meshwall update
   ```

4. **Start the web dashboard** (as normal user):
   ```bash
   meshwall web
   ```
   Open `http://127.0.0.1:22355` in your browser.

5. **(Optional) Start the active listener**:
   ```bash
   sudo meshwall listen
   ```

---

## CLI Reference

```
meshwall update                     # Fetch & apply IP blocklists
meshwall domain-update              # Fetch & apply domain blocklist (dnsmasq)
meshwall status                     # Show ipset/iptables stats
meshwall listen                     # Start real‑time scan detector
meshwall web                        # Start the web dashboard
meshwall whitelist add <IP>         # Add IP to permanent whitelist
meshwall whitelist remove <IP>
meshwall whitelist list
meshwall trace <IP>                 # Geolocate and traceroute an IP
meshwall log [--tail]               # View structured logs
meshwall stats                      # Show summary of blocked attempts
meshwall summarize [--hours 24]     # AI summary (requires Ollama)
meshwall ask "question"             # Ask AI about past events
meshwall test                       # Test connectivity to feeds
meshwall diag                       # Diagnose ipset/iptables setup
```

---

## Web Dashboard

The dashboard is a self‑hosted Flask application with a green/black cyberpunk theme. It displays:
- Total blocked IPs
- Attack map (offline canvas tiles)
- Recently blocked IPs with geolocation
- Domain checker with typosquat detection
- AI chat assistant (requires Ollama)

Access it at `http://127.0.0.1:22355` after running `meshwall web`.  
All assets are served locally – no internet required for the interface.

---

## AI Integration (Ollama)

MeshWall can use a local Ollama instance to summarise scan activity and answer natural‑language questions about your firewall logs.

### Setup

1. Install [Ollama](https://ollama.ai) and pull a small model:
   ```bash
   ollama pull phi3:mini
   ```

2. Ensure Ollama is running (`systemctl start ollama` or `ollama serve`).

### Usage

```bash
meshwall summarize --hours 24
meshwall ask "Which countries are scanning me the most?"
```

The AI chat on the web dashboard also uses this integration.

### AI Chat & Assistant

The web dashboard includes a chat interface that connects to a local Ollama model. The assistant answers questions about your MeshWall system using live data from the database; blocked IPs, recent scans, top attacking countries, and individual attacker geolocation.

**Model choice:**  
MeshWall uses an **uncensored** model to avoid refusal patterns. The default is `artifish/llama3.2-uncensored:latest` (3.6B parameters, ~2.2 GB). It runs comfortably on any machine with 8 GB RAM, including Raspberry Pi 5, mini PCs, and laptops.

To change the model, edit the `MODEL` variable in `meshwall/webapp/blueprints/ai_chat.py` or set the `OLLAMA_MODEL` environment variable. Other recommended small uncensored models:

- `dolphin3.0-mistral-7b:q4_K_M`
- `hermes3:8b-llama3.1-q4_K_M`
- `qwen2.5-coder:7b-instruct-q4_K_M`
- `tinyllama:latest` (lightest)

**No data leaves your machine** ; all inference runs locally.

---

## Docker Deployment

A `Dockerfile` and `docker-compose.yml` are provided for easy containerised deployment.

```bash
docker-compose up -d
```

The web dashboard will be available on port `22355`.  
Make sure to set the environment variables `MESHWALL_ENCRYPTION_KEY` and `MESHWALL_SALT` for production use.

---

## Systemd Integration

Enable daily automatic updates and persistent monitoring:

```bash
sudo cp scripts/meshwall-fetch.timer /etc/systemd/system/
sudo cp scripts/meshwall-fetch.service /etc/systemd/system/
sudo systemctl enable --now meshwall-fetch.timer

sudo cp scripts/meshwall-listener.service /etc/systemd/system/
sudo systemctl enable --now meshwall-listener

sudo cp scripts/meshwall-domain-update.timer /etc/systemd/system/
sudo cp scripts/meshwall-domain-update.service /etc/systemd/system/
sudo systemctl enable --now meshwall-domain-update.timer
```

---

## Troubleshooting

- **`meshwall web` shows 500 error**: Check the terminal output for the exact error. Often caused by missing database tables – run `python -c "from meshwall.db import init_db; init_db()"` to create them.
- **Dashboard shows 0 blocked IPs**: Run `sudo meshwall update` to populate the database, then refresh.
- **Map not showing**: Make sure `leaflet.js`, `leaflet.css`, and `offline-tiles.js` are present in `webapp/static/`. See the self‑hosting guide in the repository.
- **AI features not working**: Verify Ollama is running (`curl http://localhost:11434/api/tags`). Install the AI dependencies with `pip install ".[ai]"`.

For more help, open an issue on GitHub.

---

## Acknowledgements

MeshWall is built with Love by Nyakki Labs, powered by the open‑source community. Special thanks to the maintainers of Firehol, Spamhaus, Feodo Tracker, and all the blocklist providers.

---

##  Stay Secure

MeshWall turns your machine into an active sentinel – every port is a tripwire.  
