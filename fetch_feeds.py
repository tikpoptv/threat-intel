#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Set

import requests

# =========================
# Configurable threat feeds
# =========================
DEFAULT_FEEDS = {
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "firehol_level1": "https://iplists.firehol.org/files/firehol_level1.netset",
}

COMMENT_PREFIXES = ("#", ";", "//")
REQUEST_TIMEOUT = 20

# Regex สำหรับจับ IP/CIDR จากแต่ละบรรทัด
CIDR_OR_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
)


def setup_logger(log_file: Path, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("threat-intel")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def fetch_text(url: str, logger: logging.Logger) -> str:
    logger.info("Fetching: %s", url)
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.text


def is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return any(stripped.startswith(prefix) for prefix in COMMENT_PREFIXES)


def normalize_entry(raw: str) -> str | None:
    """
    แปลง entry ให้เป็น canonical form:
    - IP เดี่ยว -> x.x.x.x
    - subnet -> a.b.c.d/prefix
    """
    raw = raw.strip()

    try:
        if "/" in raw:
            network = ipaddress.ip_network(raw, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                return str(network)
            return None
        else:
            ip = ipaddress.ip_address(raw)
            if isinstance(ip, ipaddress.IPv4Address):
                return str(ip)
            return None
    except ValueError:
        return None


def extract_entries(text: str, logger: logging.Logger, source_name: str) -> Set[str]:
    results: Set[str] = set()
    lines = text.splitlines()

    for line in lines:
        if is_comment_or_empty(line):
            continue

        # ดึง token แรกที่เป็น IP/CIDR จากบรรทัด
        matches = CIDR_OR_IP_RE.findall(line)
        for candidate in matches:
            normalized = normalize_entry(candidate)
            if normalized:
                results.add(normalized)

    logger.info("Parsed %s entries from %s", len(results), source_name)
    return results


def save_output(entries: Iterable[str], output_file: Path, metadata_file: Path) -> None:
    sorted_entries = sorted(
        entries,
        key=lambda x: (
            "/" not in x,  # ให้ subnet มาก่อน IP เดี่ยวหรือกลับกันก็ได้
            tuple(int(part) for part in x.split("/")[0].split(".")),
            int(x.split("/")[1]) if "/" in x else 32,
        ),
    )

    output_file.write_text("\n".join(sorted_entries) + "\n", encoding="utf-8")

    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(sorted_entries),
        "output_file": str(output_file),
    }

    import json
    metadata_file.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and merge threat intelligence feeds into a pfSense-friendly blocklist."
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to write threat_list.txt and metadata.json",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory to write update.log",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    base_dir = Path.cwd()
    output_dir = base_dir / args.output_dir
    log_dir = base_dir / args.log_dir

    ensure_dirs(output_dir, log_dir)

    log_file = log_dir / "update.log"
    logger = setup_logger(log_file, verbose=args.verbose)

    output_file = output_dir / "threat_list.txt"
    metadata_file = output_dir / "metadata.json"

    all_entries: Set[str] = set()
    failed_sources: List[str] = []

    logger.info("=== Threat feed update started ===")

    for source_name, url in DEFAULT_FEEDS.items():
        try:
            text = fetch_text(url, logger)
            entries = extract_entries(text, logger, source_name)
            before = len(all_entries)
            all_entries.update(entries)
            added = len(all_entries) - before
            logger.info(
                "Merged %s: +%d new entries, total=%d",
                source_name,
                added,
                len(all_entries),
            )
        except Exception as exc:
            failed_sources.append(source_name)
            logger.exception("Failed source %s: %s", source_name, exc)

    if not all_entries:
        logger.error("No entries collected from any source. Output not updated.")
        return 1

    save_output(all_entries, output_file, metadata_file)

    logger.info("Saved blocklist to: %s", output_file)
    logger.info("Saved metadata to: %s", metadata_file)
    logger.info("Final total entries: %d", len(all_entries))

    if failed_sources:
        logger.warning("Some feeds failed: %s", ", ".join(failed_sources))
    else:
        logger.info("All feeds fetched successfully.")

    logger.info("=== Threat feed update completed ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())