# Threat Intel Feed Aggregator

Fetches IP blocklists from multiple threat intelligence sources, deduplicates them, and outputs a single merged file for use with pfSense or any other firewall.

## Feeds

| Feed | Type |
|------|------|
| Spamhaus DROP | Subnets used for spam/cybercrime |
| Spamhaus EDROP | Extended DROP list |
| FireHOL Level 1 | Highest-confidence bad IPs |
| Feodo Tracker | C2 botnet IPs (abuse.ch) |
| Emerging Threats | Known bad IPs from the security community |
| Blocklist.de | Brute-force attackers |

## Requirements

- Python 3.8+
- pip

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Run via script (recommended)
./run_update.sh

# Or run directly
python3 fetch_feeds.py

# Verbose mode
python3 fetch_feeds.py --verbose
```

## Output

| File | Description |
|------|-------------|
| `output/threat_list.txt` | Sorted IP/CIDR blocklist |
| `output/metadata.json` | Last update time and entry count |
| `logs/update.log` | Execution log |

## Usage with pfSense

Host `output/threat_list.txt` on a web server and configure **pfBlockerNG** or a firewall alias to fetch it automatically.

## Cron (Auto-update)

```bash
# Update daily at 02:00
0 2 * * * /path/to/threat-intel/run_update.sh
```
