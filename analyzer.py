"""NetProbe aktarım loglarını analiz eder ve performans grafikleri üretir."""

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
    """Log detaylarındaki noktalı virgülle ayrılmış key=value alanlarını çözer."""

    parsed: dict[str, str] = {}
    for part in details.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def parse_integrity(value: Any) -> bool | None:
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "ok", "passed"}:
        return True
    if normalized in {"false", "0", "no", "failed"}:
        return False
    return None


def analyze_log(log_path: str) -> dict[str, float | int | str]:
    events = read_events(log_path)
    if not events:
        raise ValueError(f"{log_path} içinde olay bulunamadı")

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

    # Throughput: retransmission ve yapay kayıp denemeleri dahil gönderilmeye çalışılan DATA byte miktarı.
    # Goodput: alıcıda başarıyla yeniden oluşturulan gerçek dosya byte miktarı.
    data_payload_bytes_attempted = sum(
        int(as_float(row.get("payload_bytes"))) for row in data_send_events + simulated_loss_events
    )
    completion_events = [row for row in events if row.get("event") == "transfer_completed"]
    reconstruction_events = [row for row in events if row.get("event") == "file_reconstructed"]
    original_file_bytes = 0
    if completion_events:
        completion_details = parse_details(completion_events[-1].get("details", ""))
        original_file_bytes = int(as_float(completion_details.get("original_file_size"), completion_events[-1].get("payload_bytes")))
        completion_time = as_float(completion_details.get("total_transfer_time"), completion_time)
    elif reconstruction_events:
        reconstruction_details = parse_details(reconstruction_events[-1].get("details", ""))
        original_file_bytes = int(as_float(reconstruction_details.get("original_file_size"), reconstruction_events[-1].get("payload_bytes")))
        completion_time = as_float(reconstruction_details.get("total_transfer_time"), completion_time)
    else:
        original_file_bytes = data_payload_bytes_attempted

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
    integrity_ok: bool | str = "UNKNOWN"
    if reconstruction_events:
        reconstruction_details = parse_details(reconstruction_events[-1].get("details", ""))
        duplicate_count = int(as_float(reconstruction_details.get("duplicate_count"), duplicate_count))
        parsed_integrity = parse_integrity(
            reconstruction_events[-1].get("integrity_ok") or reconstruction_details.get("integrity_ok")
        )
        if parsed_integrity is not None:
            integrity_ok = parsed_integrity

    if integrity_ok == "UNKNOWN":
        for row in reversed(events):
            parsed_integrity = parse_integrity(row.get("integrity_ok"))
            if parsed_integrity is None:
                parsed_integrity = parse_integrity(parse_details(row.get("details", "")).get("integrity_ok"))
            if parsed_integrity is not None:
                integrity_ok = parsed_integrity
                break

    throughput = data_payload_bytes_attempted / completion_time if completion_time > 0 else 0.0
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
        "transferred_bytes": data_payload_bytes_attempted,
        "data_bytes_sent": data_payload_bytes_attempted,
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
            "Paket Boyutu (byte)",
            ["goodput", "throughput"],
            "Byte / saniye",
            "Paket Boyutu - Throughput ve Goodput",
            "packet_size_results.png",
        ),
        (
            "timeout",
            "timeout",
            "Timeout (saniye)",
            ["retransmission_count", "completion_time"],
            "Sayı / saniye",
            "Timeout - Yeniden Gönderim Sayısı ve Tamamlanma Süresi",
            "timeout_results.png",
        ),
        (
            "loss_rate",
            "loss_rate",
            "Yapay Kayıp Oranı",
            ["goodput", "throughput", "retransmission_rate"],
            "Byte/s veya oran",
            "Kayıp Oranı - Goodput, Throughput ve Yeniden Gönderim Oranı",
            "loss_rate_results.png",
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


def save_experiment_results_json(results_csv: str, output_dir: str) -> str:
    """Deney CSV çıktısının JSON kopyasını üretir."""

    data = pd.read_csv(results_csv)
    json_path = os.path.join(output_dir, "experiment_results.json")
    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(data.to_dict(orient="records"), json_file, indent=2)
    return json_path


def metric_change_text(start: float, end: float, unit: str = "") -> str:
    if start == 0:
        return f"{end:.4f}{unit}"
    change = ((end - start) / start) * 100
    direction = "arttı" if change >= 0 else "azaldı"
    return f"{abs(change):.2f}% {direction} ({start:.4f}{unit} -> {end:.4f}{unit})"


def generate_technical_interpretation(results_csv: str, output_dir: str) -> str:
    """Deney sonuçlarından rapora eklenebilecek kısa Türkçe yorum üretir."""

    os.makedirs(output_dir, exist_ok=True)
    data = pd.read_csv(results_csv)
    lines = [
        "NetProbe Teknik Deney Yorumu",
        "=============================",
        "",
        "Bu yorumlar, UDP üzerinde Stop-and-Wait ARQ kullanan NetProbe deney çıktılarından otomatik üretilmiştir.",
        "",
    ]

    packet_data = data[data["scenario"] == "packet_size"].sort_values("packet_size")
    if len(packet_data) >= 2:
        first = packet_data.iloc[0]
        last = packet_data.iloc[-1]
        lines.extend(
            [
                "1. Paket boyutunun etkisi",
                (
                    f"Paket boyutu {int(first['packet_size'])} bayttan {int(last['packet_size'])} bayta çıktığında "
                    f"goodput {metric_change_text(float(first['goodput']), float(last['goodput']), ' B/s')}. "
                    "Daha büyük paketler aynı dosya için daha az ACK bekleme turu oluşturduğu için Stop-and-Wait "
                    "mekanizmasında protokol ek yükü azalır. Kayıp yoksa throughput ve goodput genellikle artar; "
                    "ancak çok büyük paketler gerçek ağda kayıp maliyetini artırabilir."
                ),
                "",
            ]
        )

    timeout_data = data[data["scenario"] == "timeout"].sort_values("timeout")
    if len(timeout_data) >= 2:
        first = timeout_data.iloc[0]
        last = timeout_data.iloc[-1]
        lines.extend(
            [
                "2. Timeout değerinin etkisi",
                (
                    f"Timeout {float(first['timeout']):.2f} saniyeden {float(last['timeout']):.2f} saniyeye çıktığında "
                    f"retransmission sayısı {metric_change_text(float(first['retransmission_count']), float(last['retransmission_count']))}. "
                    "Timeout çok küçük seçilirse ACK yolda olsa bile paket kaybolmuş gibi kabul edilebilir ve gereksiz "
                    "yeniden gönderimler oluşabilir. Timeout çok büyük seçilirse gerçek kayıp durumunda istemci daha uzun "
                    "bekler ve completion time artabilir."
                ),
                "",
            ]
        )

    loss_data = data[data["scenario"] == "loss_rate"].sort_values("loss_rate")
    if len(loss_data) >= 2:
        first = loss_data.iloc[0]
        last = loss_data.iloc[-1]
        lines.extend(
            [
                "3. Yapay paket kaybının etkisi",
                (
                    f"Kayıp oranı {float(first['loss_rate']):.2f} değerinden {float(last['loss_rate']):.2f} değerine çıktığında "
                    f"retransmission rate {metric_change_text(float(first['retransmission_rate']), float(last['retransmission_rate']))}; "
                    f"goodput ise {metric_change_text(float(first['goodput']), float(last['goodput']), ' B/s')}. "
                    "Kayıp arttıkça istemci daha fazla timeout yaşar ve aynı sequence number için yeniden gönderim yapar. "
                    "Bu durum aktarılan toplam veri denemelerini artırırken faydalı veri hızını düşürebilir."
                ),
                "",
            ]
        )

    lines.extend(
        [
            "4. Bütünlük ve duplicate paketler",
            (
                "Her aktarım sonunda sunucuda oluşturulan dosyanın SHA-256 değeri istemcinin gönderdiği hash ile "
                "karşılaştırılır. integrity_ok=True sonucu dosyanın eksiksiz ve doğru sırada yeniden oluşturulduğunu "
                "gösterir. Duplicate DATA paketi gelirse sunucu aynı veriyi ikinci kez yazmaz; yalnızca ilgili ACK'i "
                "yeniden gönderir."
            ),
            "",
        ]
    )

    interpretation_path = os.path.join(output_dir, "technical_interpretation.txt")
    with open(interpretation_path, "w", encoding="utf-8") as output_file:
        output_file.write("\n".join(lines))
    return interpretation_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetProbe loglarını analiz eder")
    parser.add_argument("--log", help="Analiz edilecek istemci CSV logu")
    parser.add_argument("--results-csv", help="Grafik üretilecek deney sonuçları CSV dosyası")
    parser.add_argument("--output-dir", default=RESULTS_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if not args.log and not args.results_csv:
        raise SystemExit("Metrik için --log veya grafik için --results-csv verin.")

    if args.log:
        metrics = analyze_log(args.log)
        csv_path, json_path = save_metrics(metrics, args.output_dir)
        print(json.dumps(metrics, indent=2))
        print(f"Analiz kaydedildi: {csv_path} ve {json_path}")

    if args.results_csv:
        json_path = save_experiment_results_json(args.results_csv, args.output_dir)
        graph_paths = plot_experiment_results(args.results_csv, args.output_dir)
        interpretation_path = generate_technical_interpretation(args.results_csv, args.output_dir)
        print(f"Deney JSON çıktısı kaydedildi: {json_path}")
        print("Grafikler oluşturuldu:")
        for graph_path in graph_paths:
            print(f"  {graph_path}")
        print(f"Teknik yorum kaydedildi: {interpretation_path}")


if __name__ == "__main__":
    main()
