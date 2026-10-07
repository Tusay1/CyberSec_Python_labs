"""Завдання 2: CLI-аналізатор журналів веб-сервера (Варіант 1)."""

import csv
import json
import logging
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

LOG_LINE_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^\"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

ATTACK_SIGNATURES = {
    "SQLi": re.compile(
        r"(\bUNION\b|\bSELECT\b|--|' OR '1'='1|;\s*DROP\b)", re.IGNORECASE
    ),
    "Directory Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd)", re.IGNORECASE),
    "XSS": re.compile(
        r"(<script\b|javascript:|onerror=|onload=|alert\()", re.IGNORECASE
    ),
}


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    uri: str
    status: int
    size: int


@dataclass
class AttackAlert:
    attack_type: str
    ip: str
    uri: str
    timestamp: str


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("web_analyzer")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def parse_timestamp(ts_str: str) -> datetime:
    raw = ts_str.split()[0]
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S")


def parse_log_file(
    file_path: Path, min_status: int = 400
) -> tuple[list[LogEntry], list[AttackAlert], Counter]:
    entries: list[LogEntry] = []
    attacks: list[AttackAlert] = []
    error_ips: Counter = Counter()

    if not file_path.exists():
        raise FileNotFoundError(f"Файл логу не знайдено: {file_path}")

    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            match = LOG_LINE_REGEX.match(line)
            if not match:
                continue

            data = match.groupdict()
            try:
                status = int(data["status"])
                size = int(data["size"]) if data["size"].isdigit() else 0
                ts = parse_timestamp(data["time"])
            except ValueError:
                continue

            entry = LogEntry(
                ip=data["ip"],
                timestamp=ts,
                method=data["method"],
                uri=data["uri"],
                status=status,
                size=size,
            )
            entries.append(entry)

            if status >= min_status:
                error_ips[entry.ip] += 1

            for att_type, regex in ATTACK_SIGNATURES.items():
                if regex.search(entry.uri):
                    attacks.append(
                        AttackAlert(
                            attack_type=att_type,
                            ip=entry.ip,
                            uri=f"{entry.method} {entry.uri}",
                            timestamp=entry.timestamp.isoformat(),
                        )
                    )

    return entries, attacks, error_ips


def export_report(
    output_path: Path,
    out_format: str,
    top_errors: list[tuple[str, int]],
    attacks: list[AttackAlert],
    total_processed: int,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if out_format == "json":
        report_data = {
            "total_processed": total_processed,
            "top_error_ips": [{"ip": ip, "errors": cnt} for ip, cnt in top_errors],
            "attacks_detected": [asdict(a) for a in attacks],
        }
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
    else:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Section", "Item1", "Item2", "Item3"])
            writer.writerow(["SUMMARY", "Total Entries", total_processed, ""])
            for ip, cnt in top_errors:
                writer.writerow(["TOP_ERROR_IP", ip, cnt, ""])
            for a in attacks:
                writer.writerow(["ALERT", a.attack_type, a.ip, a.uri])


def run_analyzer(
    log_file: str,
    output: str | None = None,
    min_status: int = 400,
    top: int = 5,
    out_format: str = "json",
) -> None:
    logger = setup_logger()
    path = Path(log_file)

    logger.info("Loading access log from %s...", path)
    entries, attacks, error_ips = parse_log_file(path, min_status=min_status)

    if not entries:
        logger.warning("No valid log entries found.")
        return

    first_time = min(e.timestamp for e in entries)
    last_time = max(e.timestamp for e in entries)
    logger.info(
        "Processed %d log entries from %s to %s.",
        len(entries),
        first_time.strftime("%Y-%m-%d %H:%M:%S"),
        last_time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    print(f"\n=== Top-{top} IP Addresses with Error Statuses (>={min_status}) ===")
    top_errors = error_ips.most_common(top)
    for ip, count in top_errors:
        print(f"{ip:<18} {count} errors")

    print("\n=== Detected Attack Signatures ===")
    for alert in attacks:
        print(
            f'[ALERT] Potential {alert.attack_type} attack from {alert.ip}: "{alert.uri}"'
        )

    if output:
        out_p = Path(output)
        export_report(out_p, out_format, top_errors, attacks, len(entries))
        logger.info("Analysis report saved to %s", out_p)
