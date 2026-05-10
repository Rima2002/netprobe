"""Analyze NetProbe transfer logs and generate performance graphs."""

from __future__ import annotations

import argparse
import csv
import json
import os
from statistics import mean
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd

try:
    from .config import RESULTS_DIR
except ImportError:
    from config import RESULTS_DIR


def read_events(log_path: str) -> list[dict[str, Any]]:
    with open(log_path, newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_details(details: str) -> dict[str, str]:
    """Parse semicolon-separated key=value fields from log details."""

    parsed: dict[str, str] = {}
    for part in details.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "ok"}


def analyze_log(log_path: str) -> dict[str, float | int | str]:
    events = read_events(log_path)
    if not events:
        raise ValueError(f"No events found in {log_path}")

    timestamps = [as_float(row["timestamp"]) for row in events if row.get("timestamp")]
    completion_time = max(timestamps) - min(timestamps) if timestamps else 0.0

    data_send_events = [row for row in events if row.get("event") == "packet_sent" and row.get("packet_type") == "DATA"]
    simulated_loss_events = [
        row for row in events if row.get("event") == "simulated_packet_loss" and row.get("packet_type") == "DATA"
    ]
    timeout_events = [row for row in events if row.get("event") == "timeout"]
    failed_events = [row for row in events if row.get("event") == "packet_failed"]
    duplicate_events = [row for row in events if row.get("event") == "duplicate_packet_ignored"]
    successful_data_acks = [
        row
        for row in events
        if row.get("event") == "ack_received"
        and row.get("packet_type") == "ACK"
        and "ack_for=DATA" in row.get("details", "")
    ]

    transferred_bytes = sum(int(as_float(row.get("payload_bytes"))) for row in data_send_events)
    completion_events = [row for row in events if row.get("event") == "transfer_completed"]
    reconstruction_events = [row for row in events if row.get("event") == "file_reconstructed"]
    original_file_bytes = 0
    if completion_events:
        completion_details = parse_details(completion_events[-1].get("details", ""))
        original_file_bytes = int(as_float(completion_details.get("original_file_size"), completion_events[-1].get("payload_bytes")))
        transferred_bytes = int(as_float(completion_details.get("transferred_bytes"), transferred_bytes))
        completion_time = as_float(completion_details.get("total_transfer_time"), completion_time)
    elif reconstruction_events:
        reconstruction_details = parse_details(reconstruction_events[-1].get("details", ""))
        original_file_bytes = int(as_float(reconstruction_details.get("original_file_size"), reconstruction_events[-1].get("payload_bytes")))
        transferred_bytes = int(as_float(reconstruction_details.get("transferred_bytes"), original_file_bytes))
        completion_time = as_float(reconstruction_details.get("total_transfer_time"), completion_time)
    else:
        original_file_bytes = transferred_bytes

    attempted_sends = len(data_send_events) + len(simulated_loss_events)
    retransmission_events = [
        row
        for row in events
        if row.get("event") in {"packet_sent", "simulated_packet_loss"}
        and row.get("packet_type") == "DATA"
        and int(as_float(row.get("attempt"), 1)) > 1
    ]
    retransmission_count = len(retransmission_events)

    rtts = [
        as_float(row.get("rtt"))
        for row in events
        if row.get("event") == "ack_received" and row.get("rtt") not in ("", None)
    ]

    duplicate_count = len(duplicate_events)
    integrity_ok = ""
    if reconstruction_events:
        reconstruction_details = parse_details(reconstruction_events[-1].get("details", ""))
        duplicate_count = int(as_float(reconstruction_details.get("duplicate_count"), duplicate_count))
        integrity_ok = str(as_bool(reconstruction_details.get("integrity_ok")))

    throughput = transferred_bytes / completion_time if completion_time > 0 else 0.0
    goodput = original_file_bytes / completion_time if completion_time > 0 else 0.0
    packet_loss_rate = len(simulated_loss_events) / attempted_sends if attempted_sends else 0.0
    retransmission_rate = retransmission_count / attempted_sends if attempted_sends else 0.0
    average_rtt = mean(rtts) if rtts else 0.0

    return {
        "log_file": log_path,
        "file_size": original_file_bytes,
        "throughput": throughput,
        "goodput": goodput,
        "completion_time": completion_time,
        "average_rtt": average_rtt,
        "throughput_bytes_per_second": throughput,
        "goodput_bytes_per_second": goodput,
        "packet_loss_rate": packet_loss_rate,
        "retransmission_count": retransmission_count,
        "retransmission_rate": retransmission_rate,
        "average_rtt_seconds": average_rtt,
        "completion_time_seconds": completion_time,
        "duplicate_count": duplicate_count,
        "integrity_ok": integrity_ok,
        "successful_packet_count": len(successful_data_acks),
        "failed_packet_count": len(failed_events),
        "timeout_count": len(timeout_events),
        "transferred_bytes": transferred_bytes,
        "data_bytes_sent": transferred_bytes,
        "original_file_bytes": original_file_bytes,
    }


def save_metrics(metrics: dict[str, float | int | str], output_dir: str) -> tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "analysis_summary.csv")
    json_path = os.path.join(output_dir, "analysis_summary.json")

    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(metrics.keys()))
        writer.writeheader()
        writer.writerow(metrics)

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(metrics, json_file, indent=2)

    return csv_path, json_path


def plot_experiment_results(results_csv: str, output_dir: str) -> list[str]:
    os.makedirs(output_dir, exist_ok=True)
    data = pd.read_csv(results_csv)
    graph_paths: list[str] = []

    graph_configs = [
        (
            "packet_size",
            "packet_size",
            "Packet Size (bytes)",
            ["goodput", "throughput"],
            "Bytes / second",
            "Packet Size vs Throughput and Goodput",
            "packet_size_throughput_goodput.png",
        ),
        (
            "packet_size",
            "packet_size",
            "Packet Size (bytes)",
            ["completion_time"],
            "Seconds",
            "Packet Size vs Completion Time",
            "packet_size_completion_time.png",
        ),
        (
            "timeout",
            "timeout",
            "Timeout (seconds)",
            ["retransmission_count"],
            "Retransmitted packets",
            "Timeout vs Retransmission Count",
            "timeout_retransmission_count.png",
        ),
        (
            "timeout",
            "timeout",
            "Timeout (seconds)",
            ["completion_time"],
            "Seconds",
            "Timeout vs Completion Time",
            "timeout_completion_time.png",
        ),
        (
            "loss_rate",
            "loss_rate",
            "Artificial Loss Rate",
            ["goodput", "throughput"],
            "Bytes / second",
            "Loss Rate vs Throughput and Goodput",
            "loss_rate_throughput_goodput.png",
        ),
        (
            "loss_rate",
            "loss_rate",
            "Artificial Loss Rate",
            ["retransmission_rate"],
            "Retransmissions / attempted sends",
            "Loss Rate vs Retransmission Rate",
            "loss_rate_retransmission_rate.png",
        ),
    ]

    for scenario_name, x_column, x_label, y_columns, y_label, title, filename in graph_configs:
        subset = data[data["scenario"] == scenario_name].sort_values(by=x_column)
        if subset.empty:
            continue

        plt.figure(figsize=(9, 5))
        for y_column in y_columns:
            label = y_column.replace("_", " ").title()
            plt.plot(subset[x_column], subset[y_column], marker="o", label=label)
        plt.xlabel(x_label)
        plt.ylabel(y_label)
        plt.title(f"NetProbe: {title}")
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()

        graph_path = os.path.join(output_dir, filename)
        plt.savefig(graph_path)
        plt.close()
        graph_paths.append(graph_path)

    return graph_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze NetProbe logs")
    parser.add_argument("--log", help="Client CSV log to analyze")
    parser.add_argument("--results-csv", help="Experiment results CSV to graph")
    parser.add_argument("--output-dir", default=RESULTS_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if not args.log and not args.results_csv:
        raise SystemExit("Provide --log for metrics or --results-csv for graphs.")

    if args.log:
        metrics = analyze_log(args.log)
        csv_path, json_path = save_metrics(metrics, args.output_dir)
        print(json.dumps(metrics, indent=2))
        print(f"Analysis saved: {csv_path} and {json_path}")

    if args.results_csv:
        graph_paths = plot_experiment_results(args.results_csv, args.output_dir)
        print("Graphs generated:")
        for graph_path in graph_paths:
            print(f"  {graph_path}")


if __name__ == "__main__":
    main()
