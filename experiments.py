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


def ensure_test_file(path: str, size_kb: int = 256) -> None:
    if os.path.exists(path):
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)
    pattern = b"NetProbe reliable UDP transfer experiment data.\n"
    with open(path, "wb") as file_obj:
        while file_obj.tell() < size_kb * 1024:
            file_obj.write(pattern)


def latest_client_log(log_dir: str, before: set[str]) -> str:
    candidates = set(glob.glob(os.path.join(log_dir, "client_transfer_*.csv"))) - before
    if not candidates:
        raise FileNotFoundError("No new client log was created")
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
) -> str:
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    before_logs = set(glob.glob(os.path.join(log_dir, "client_transfer_*.csv")))

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

    return latest_client_log(log_dir, before_logs)


def run_experiments(
    file_path: str,
    port: int,
    max_retries: int,
    log_dir: str,
    output_dir: str,
) -> tuple[str, list[str]]:
    ensure_test_file(file_path)

    scenarios: list[dict[str, Any]] = []
    for packet_size in [512, 1024, 2048]:
        scenarios.append(
            {
                "scenario": "packet_size",
                "packet_size": packet_size,
                "timeout": 1.0,
                "loss_rate": 0.05,
            }
        )

    for timeout in [0.2, 0.5, 1.0]:
        scenarios.append(
            {
                "scenario": "timeout",
                "packet_size": 1024,
                "timeout": timeout,
                "loss_rate": 0.05,
            }
        )

    for loss_rate in [0.0, 0.1, 0.2]:
        scenarios.append(
            {
                "scenario": "loss_rate",
                "packet_size": 1024,
                "timeout": 1.0,
                "loss_rate": loss_rate,
            }
        )

    results: list[dict[str, Any]] = []
    current_port = port
    for index, scenario in enumerate(scenarios, start=1):
        print(f"Running experiment {index}/{len(scenarios)}: {scenario}")
        log_path = run_one_transfer(
            file_path=file_path,
            port=current_port,
            packet_size=int(scenario["packet_size"]),
            timeout=float(scenario["timeout"]),
            loss_rate=float(scenario["loss_rate"]),
            max_retries=max_retries,
            log_dir=log_dir,
            output_dir=output_dir,
        )
        metrics = analyze_log(log_path)
        results.append({**scenario, **metrics})
        current_port += 1

    os.makedirs(output_dir, exist_ok=True)
    results_csv = os.path.join(output_dir, "experiment_results.csv")
    with open(results_csv, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    graph_paths = plot_experiment_results(results_csv, output_dir)
    return results_csv, graph_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run NetProbe performance experiments")
    parser.add_argument(
        "--file",
        default=os.path.join(BASE_DIR, TEST_FILES_DIR, "sample.txt"),
        help="File used for all experiment transfers",
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

