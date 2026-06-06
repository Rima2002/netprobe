"""NetProbe aktarımları için CSV/JSON olay loglama."""

from __future__ import annotations

import csv
import json
import os
import time
from typing import Any


FIELDNAMES = [
    "timestamp",
    "event",
    "packet_type",
    "sequence_number",
    "attempt",
    "payload_bytes",
    "rtt",
    "integrity_ok",
    "details",
]


class EventLogger:
    """Aktarım olaylarını toplar ve CSV/JSON dosyalarına yazar."""

    def __init__(self, log_dir: str, prefix: str = "transfer") -> None:
        os.makedirs(log_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        stamp = f"{stamp}_{int((time.time() % 1) * 1000):03d}"
        self.csv_path = os.path.join(log_dir, f"{prefix}_{stamp}.csv")
        self.json_path = os.path.join(log_dir, f"{prefix}_{stamp}.json")
        self.events: list[dict[str, Any]] = []

    def log(
        self,
        event: str,
        packet_type: str = "",
        sequence_number: int | str = "",
        attempt: int | str = "",
        payload_bytes: int | str = "",
        rtt: float | str = "",
        integrity_ok: bool | str = "",
        details: str = "",
    ) -> None:
        row = {
            "timestamp": time.time(),
            "event": event,
            "packet_type": packet_type,
            "sequence_number": sequence_number,
            "attempt": attempt,
            "payload_bytes": payload_bytes,
            "rtt": rtt,
            "integrity_ok": integrity_ok,
            "details": details,
        }
        self.events.append(row)

    def save(self) -> tuple[str, str]:
        with open(self.csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(self.events)

        with open(self.json_path, "w", encoding="utf-8") as json_file:
            json.dump(self.events, json_file, indent=2)

        return self.csv_path, self.json_path
