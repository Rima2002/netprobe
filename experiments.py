"""Run repeatable NetProbe experiments and graph the results."""

from __future__ import annotations

import argparse
import csv
import glob
import os
import subprocess
import sys
import time
from typing import Any

try:
    from .analyzer import analyze_log, plot_experiment_results
    from .config import DEFAULT_MAX_RETRIES, LOGS_DIR, RESULTS_DIR, TEST_FILES_DIR
except ImportError:
    from analyzer import analyze_log, plot_experiment_results
    from config import DEFAULT_MAX_RETRIES, LOGS_DIR, RESULTS_DIR, TEST_FILES_DIR


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILE_SPECS = {
    "small": ("small.bin", 64 * 1024),
    "medium": ("medium.bin", 1024 * 1024),
    "large": ("large.bin", 10 * 1024 * 1024),
}


def ensure_test_file(path: str, size_bytes: int) -> None:
    if os.path.exists(path) and os.path.getsize(path) >= size_bytes:
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)
    pattern = (f"NetProbe deterministic test data for {os.path.basename(path)}.\n").encode("utf-8")
    with open(path, "wb") as file_obj:
        while file_obj.tell() < size_bytes:
            remaining = size_bytes - file_obj.tell()
            file_obj.write(pattern[:remaining])


def ensure_standard_test_files(test_dir: str) -> dict[str, str]:
    paths: dict[str, str] = {}
    for key, (filename, size_bytes) in TEST_FILE_SPECS.items():
        path = os.path.join(test_dir, filename)
        ensure_test_file(path, size_bytes)
        paths[key] = path
    return paths


def latest_log(log_dir: str, prefix: str, before: set[str]) -> str:
    candidates = set(glob.glob(os.path.join(log_dir, f"{prefix}_*.csv"))) - before
    if not candidates:
        raise FileNotFoundError(f"No new {prefix} log was created")
    return max(candidates, key=os.path.getmtime)


def run_one_transfer(
    file_path: str,
    port: int,
    packet_size: int,
    timeout: float,
    loss_rate: float,
    max_retries: int,
    log_dir: str,
    output_dir: str,
) -> tuple[str, str]:
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    before_logs = set(glob.glob(os.path.join(log_dir, "client_transfer_*.csv")))
    before_server_logs = set(glob.glob(os.path.join(log_dir, "server_transfer_*.csv")))

    server_cmd = [
        sys.executable,
        os.path.join(BASE_DIR, "server.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output-dir",
        os.path.join(BASE_DIR, "received_files"),
        "--log-dir",
        log_dir,
        "--once",
    ]
    client_cmd = [
        sys.executable,
        os.path.join(BASE_DIR, "client.py"),
        "--server-ip",
        "127.0.0.1",
        "--server-port",
        str(port),
        "--file",
        file_path,
        "--packet-size",
        str(packet_size),
        "--timeout",
        str(timeout),
        "--loss-rate",
        str(loss_rate),
        "--max-retries",
        str(max_retries),
        "--log-dir",
        log_dir,
    ]

    server_process = subprocess.Popen(
        server_cmd,
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.4)

    try:
        client_result = subprocess.run(
            client_cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if client_result.returncode != 0:
            raise RuntimeError(
                "Client failed\n"
                f"STDOUT:\n{client_result.stdout}\n"
                f"STDERR:\n{client_result.stderr}"
            )

        server_process.wait(timeout=10)
        if server_process.returncode not in (0, None):
            stdout, stderr = server_process.communicate(timeout=1)
            raise RuntimeError(f"Server failed\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
    finally:
        if server_process.poll() is None:
            server_process.terminate()
            server_process.wait(timeout=5)

    client_log = latest_log(log_dir, "client_transfer", before_logs)
    server_log = latest_log(log_dir, "server_transfer", before_server_logs)
    return client_log, server_log


def run_experiments(
    file_path: str,
    port: int,
    max_retries: int,
    log_dir: str,
    output_dir: str,
) -> tuple[str, list[str]]:
    generated_files = ensure_standard_test_files(os.path.join(BASE_DIR, TEST_FILES_DIR))
    if file_path:
        ensure_test_file(file_path, TEST_FILE_SPECS["medium"][1])
        generated_files["custom"] = file_path

    scenarios: list[dict[str, Any]] = []
    for packet_size in [512, 1024, 2048]:
        scenarios.append(
            {
                "scenario": "packet_size",
                "file_path": generated_files["medium"],
                "packet_size": packet_size,
                "timeout": 1.0,
                "loss_rate": 0.0,
            }
        )

    for timeout in [0.2, 0.5, 1.0]:
        scenarios.append(
            {
                "scenario": "timeout",
                "file_path": generated_files["small"],
                "packet_size": 1024,
                "timeout": timeout,
                "loss_rate": 0.1,
            }
        )

    for loss_rate in [0.0, 0.1, 0.2]:
        scenarios.append(
            {
                "scenario": "loss_rate",
                "file_path": generated_files["small"],
                "packet_size": 1024,
                "timeout": 0.2,
                "loss_rate": loss_rate,
            }
        )

    results: list[dict[str, Any]] = []
    current_port = port
    for index, scenario in enumerate(scenarios, start=1):
        print(f"Running experiment {index}/{len(scenarios)}: {scenario}")
        client_log, server_log = run_one_transfer(
            file_path=str(scenario["file_path"]),
            port=current_port,
            packet_size=int(scenario["packet_size"]),
            timeout=float(scenario["timeout"]),
            loss_rate=float(scenario["loss_rate"]),
            max_retries=max_retries,
            log_dir=log_dir,
            output_dir=output_dir,
        )
        client_metrics = analyze_log(client_log)
        server_metrics = analyze_log(server_log)
        results.append(
            {
                "scenario": scenario["scenario"],
                "packet_size": scenario["packet_size"],
                "timeout": scenario["timeout"],
                "loss_rate": scenario["loss_rate"],
                "file_size": client_metrics["file_size"],
                "throughput": client_metrics["throughput"],
                "goodput": client_metrics["goodput"],
                "completion_time": client_metrics["completion_time"],
                "retransmission_count": client_metrics["retransmission_count"],
                "retransmission_rate": client_metrics["retransmission_rate"],
                "packet_loss_rate": client_metrics["packet_loss_rate"],
                "average_rtt": client_metrics["average_rtt"],
                "duplicate_count": server_metrics["duplicate_count"],
                "integrity_ok": server_metrics["integrity_ok"],
                "client_log": client_log,
                "server_log": server_log,
            }
        )
        current_port += 1

    os.makedirs(output_dir, exist_ok=True)
    results_csv = os.path.join(output_dir, "experiment_results.csv")
    fieldnames = [
        "scenario",
        "packet_size",
        "timeout",
        "loss_rate",
        "file_size",
        "throughput",
        "goodput",
        "completion_time",
        "retransmission_count",
        "retransmission_rate",
        "packet_loss_rate",
        "average_rtt",
        "duplicate_count",
        "integrity_ok",
        "client_log",
        "server_log",
    ]
    with open(results_csv, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    graph_paths = plot_experiment_results(results_csv, output_dir)
    return results_csv, graph_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run NetProbe performance experiments")
    parser.add_argument(
        "--file",
        default="",
        help="Optional custom file to generate/use for experiments; defaults use small.bin and medium.bin",
    )
    parser.add_argument("--port", type=int, default=6100)
    parser.add_argument("--max-retries", type=int, default=max(DEFAULT_MAX_RETRIES, 8))
    parser.add_argument("--log-dir", default=os.path.join(BASE_DIR, LOGS_DIR))
    parser.add_argument("--output-dir", default=os.path.join(BASE_DIR, RESULTS_DIR))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    results_csv, graph_paths = run_experiments(
        file_path=args.file,
        port=args.port,
        max_retries=args.max_retries,
        log_dir=args.log_dir,
        output_dir=args.output_dir,
    )
    print(f"Experiment results saved: {results_csv}")
    print("Graphs generated:")
    for graph_path in graph_paths:
        print(f"  {graph_path}")


if __name__ == "__main__":
    main()
