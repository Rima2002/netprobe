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


def analyze_log(log_path: str) -> dict[str, float | int | str]:
    events = read_events(log_path)
    if not events:
        raise ValueError(f"No events found in {log_path}")

    timestamps = [as_float(row["timestamp"]) for row in events if row.get("timestamp")]
    completion_time = max(timestamps) - min(timestamps) if timestamps else 0.0

    data_send_events = [
        row for row in events if row.get("event") == "packet_sent" and row.get("packet_type") == "DATA"
    ]
    simulated_loss_events = [row for row in events if row.get("event") == "simulated_packet_loss"]
    timeout_events = [row for row in events if row.get("event") == "timeout"]
    failed_events = [row for row in events if row.get("event") == "packet_failed"]
    successful_data_acks = [
        row
        for row in events
        if row.get("event") == "ack_received"
        and row.get("packet_type") == "ACK"
        and "ack_for=DATA" in row.get("details", "")
    ]

    data_bytes_sent = sum(int(as_float(row.get("payload_bytes"))) for row in data_send_events)
    completion_events = [row for row in events if row.get("event") == "transfer_completed"]
    original_file_bytes = 0
    if completion_events:
        original_file_bytes = int(as_float(completion_events[-1].get("payload_bytes")))
    else:
        original_file_bytes = data_bytes_sent

    attempted_sends = len(data_send_events) + len(simulated_loss_events)
    retransmission_events = [
        row
        for row in events
        if row.get("event") in {"packet_sent", "simulated_packet_loss"} and int(as_float(row.get("attempt"), 1)) > 1
    ]
    retransmission_count = len(retransmission_events)

    rtts = [
        as_float(row.get("rtt"))
        for row in events
        if row.get("event") == "ack_received" and row.get("rtt") not in ("", None)
    ]

    throughput = data_bytes_sent / completion_time if completion_time > 0 else 0.0
    goodput = original_file_bytes / completion_time if completion_time > 0 else 0.0
    packet_loss_rate = len(simulated_loss_events) / attempted_sends if attempted_sends else 0.0
    retransmission_rate = retransmission_count / attempted_sends if attempted_sends else 0.0

    return {
        "log_file": log_path,
        "throughput_bytes_per_second": throughput,
        "goodput_bytes_per_second": goodput,
        "packet_loss_rate": packet_loss_rate,
        "retransmission_count": retransmission_count,
        "retransmission_rate": retransmission_rate,
        "average_rtt_seconds": mean(rtts) if rtts else 0.0,
        "completion_time_seconds": completion_time,
        "successful_packet_count": len(successful_data_acks),
        "failed_packet_count": len(failed_events),
        "timeout_count": len(timeout_events),
        "data_bytes_sent": data_bytes_sent,
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

    scenario_configs = [
        ("packet_size", "packet_size", "Packet Size (bytes)", "packet_size_results.png"),
        ("timeout", "timeout", "Timeout (seconds)", "timeout_results.png"),
        ("loss_rate", "loss_rate", "Artificial Loss Rate", "loss_rate_results.png"),
    ]

    for scenario_name, x_column, x_label, filename in scenario_configs:
        subset = data[data["scenario"] == scenario_name].sort_values(by=x_column)
        if subset.empty:
            continue

        plt.figure(figsize=(9, 5))
        plt.plot(subset[x_column], subset["goodput_bytes_per_second"], marker="o", label="Goodput")
        plt.plot(subset[x_column], subset["throughput_bytes_per_second"], marker="s", label="Throughput")
        plt.xlabel(x_label)
        plt.ylabel("Bytes / second")
        plt.title(f"NetProbe {scenario_name.replace('_', ' ').title()} Scenario")
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
