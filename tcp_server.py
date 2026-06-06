"""NetProbe karşılaştırma deneyleri için TCP sunucusu."""

from __future__ import annotations

import argparse
import json
import os
import socket
import time

try:
    from .config import DEFAULT_SERVER_PORT, LOGS_DIR, RECEIVED_FILES_DIR
    from .logger import EventLogger
    from .protocol import file_sha256, split_file
except ImportError:
    from config import DEFAULT_SERVER_PORT, LOGS_DIR, RECEIVED_FILES_DIR
    from logger import EventLogger
    from protocol import file_sha256, split_file


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("Veri alınırken bağlantı kapandı")
        buffer.extend(chunk)
    return bytes(buffer)


def send_exact(sock: socket.socket, data: bytes) -> None:
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionError("Socket bağlantısı koptu")
        total_sent += sent


def run_server(host: str, port: int, output_dir: str, log_dir: str, once: bool) -> None:
    os.makedirs(output_dir, exist_ok=True)
    logger = EventLogger(log_dir, prefix="tcp_server")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)

    logger.log(event="server_started", details=f"host={host}; port={port}")
    print(f"TCP NetProbe sunucusu {host}:{port} üzerinde dinliyor")

    try:
        while True:
            conn, client_address = sock.accept()
            with conn:
                start_time = time.time()
                logger.log(event="connection_accepted", details=f"client={client_address}")
                meta_length_bytes = recv_exact(conn, 4)
                meta_length = int.from_bytes(meta_length_bytes, "big")
                metadata = json.loads(recv_exact(conn, meta_length).decode("utf-8"))
                filename = os.path.basename(metadata["filename"])
                total_packets = int(metadata["total_packets"])
                expected_hash = str(metadata["file_hash"])
                expected_size = int(metadata["file_size"])
                logger.log(
                    event="transfer_metadata_received",
                    details=(
                        f"filename={filename}; total_packets={total_packets}; "
                        f"expected_size={expected_size}; expected_hash={expected_hash}"
                    ),
                )
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, filename)
                received_bytes = 0

                with open(output_path, "wb") as output_file:
                    for sequence_number in range(total_packets):
                        chunk_size_bytes = recv_exact(conn, 4)
                        chunk_size = int.from_bytes(chunk_size_bytes, "big")
                        chunk = recv_exact(conn, chunk_size)
                        output_file.write(chunk)
                        received_bytes += len(chunk)
                        logger.log(
                            event="packet_received",
                            packet_type="DATA",
                            sequence_number=sequence_number,
                            payload_bytes=len(chunk),
                            details=(
                                f"received_bytes={received_bytes}; "
                                f"packet_size={len(chunk)}; sequence_number={sequence_number}"
                            ),
                        )

                actual_hash = file_sha256(output_path)
                integrity_ok = actual_hash == expected_hash
                elapsed = time.time() - start_time
                logger.log(
                    event="file_reconstructed",
                    packet_type="DATA",
                    sequence_number=total_packets - 1,
                    payload_bytes=received_bytes,
                    integrity_ok=integrity_ok,
                    details=(
                        f"path={output_path}; expected_hash={expected_hash}; "
                        f"actual_hash={actual_hash}; integrity_ok={integrity_ok}; "
                        f"original_file_size={expected_size}; transferred_bytes={received_bytes}; "
                        f"total_transfer_time={elapsed:.6f}"
                    ),
                )
                response = json.dumps(
                    {
                        "integrity_ok": integrity_ok,
                        "expected_hash": expected_hash,
                        "actual_hash": actual_hash,
                        "transferred_bytes": received_bytes,
                        "duration": elapsed,
                    }
                ).encode("utf-8")
                send_exact(conn, len(response).to_bytes(4, "big") + response)

            if once:
                break
    finally:
        csv_path, json_path = logger.save()
        sock.close()
        print(f"TCP sunucu logları kaydedildi: {csv_path} ve {json_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetProbe TCP dosya aktarım sunucusu")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("--output-dir", default=RECEIVED_FILES_DIR)
    parser.add_argument("--log-dir", default=LOGS_DIR)
    parser.add_argument("--once", action="store_true", help="Bir başarılı aktarımdan sonra çık")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_server(
        host=args.host,
        port=args.port,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
        once=args.once,
    )


if __name__ == "__main__":
    main()
