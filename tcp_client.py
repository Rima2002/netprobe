"""NetProbe karşılaştırma deneyleri için TCP istemcisi."""

from __future__ import annotations

import argparse
import json
import os
import socket
import time

try:
    from .config import DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT, DEFAULT_PACKET_SIZE, DEFAULT_TIMEOUT, LOGS_DIR
    from .logger import EventLogger
    from .protocol import file_sha256, split_file
except ImportError:
    from config import DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT, DEFAULT_PACKET_SIZE, DEFAULT_TIMEOUT, LOGS_DIR
    from logger import EventLogger
    from protocol import file_sha256, split_file


def send_exact(sock: socket.socket, data: bytes) -> None:
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionError("Socket bağlantısı koptu")
        total_sent += sent


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("Veri alınırken bağlantı kapandı")
        buffer.extend(chunk)
    return bytes(buffer)


def send_file(server_ip: str, server_port: int, file_path: str, packet_size: int, timeout: float, log_dir: str) -> bool:
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    logger = EventLogger(log_dir, prefix="tcp_client")
    server_address = (server_ip, server_port)
    chunks = split_file(file_path, packet_size)
    total_packets = len(chunks)
    file_hash = file_sha256(file_path)
    file_size = os.path.getsize(file_path)
    metadata = {
        "filename": os.path.basename(file_path),
        "total_packets": total_packets,
        "file_hash": file_hash,
        "file_size": file_size,
    }
    metadata_bytes = json.dumps(metadata).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.time()

    logger.log(
        event="transfer_started",
        details=(
            f"server={server_ip}:{server_port}; file={file_path}; "
            f"size={file_size}; packet_size={packet_size}; timeout={timeout}; "
            f"protocol=TCP"
        ),
    )

    try:
        sock.connect(server_address)
        send_exact(sock, len(metadata_bytes).to_bytes(4, "big") + metadata_bytes)

        for sequence_number, chunk in enumerate(chunks):
            send_exact(sock, len(chunk).to_bytes(4, "big") + chunk)
            logger.log(
                event="packet_sent",
                packet_type="DATA",
                sequence_number=sequence_number,
                attempt=1,
                payload_bytes=len(chunk),
                details=(
                    f"send_time={time.time()}; packet_size={len(chunk)}; "
                    f"sequence_number={sequence_number}"
                ),
            )

        response_length = int.from_bytes(recv_exact(sock, 4), "big")
        response = json.loads(recv_exact(sock, response_length).decode("utf-8"))
        completion_time = time.time() - start_time
        integrity_ok = response.get("integrity_ok", False)
        logger.log(
            event="transfer_completed",
            payload_bytes=file_size,
            integrity_ok=integrity_ok,
            details=(
                f"successful_packet_count={total_packets}; "
                f"failed_packet_count=0; total_retransmissions=0; "
                f"original_file_size={file_size}; transferred_bytes={file_size}; "
                f"total_transfer_time={completion_time:.6f}; sha256={file_hash}; "
                f"expected_hash={response.get('expected_hash', file_hash)}; "
                f"actual_hash={response.get('actual_hash', 'UNKNOWN')}; "
                f"integrity_ok={integrity_ok}"
            ),
        )
        return True
    finally:
        logger.log(
            event="transfer_finished",
            payload_bytes=file_size,
            details=f"elapsed={time.time() - start_time:.6f}; total_packets={total_packets}",
        )
        csv_path, json_path = logger.save()
        sock.close()
        print(f"TCP logları kaydedildi: {csv_path} ve {json_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetProbe TCP dosya aktarım istemcisi")
    parser.add_argument("--server-ip", default=DEFAULT_SERVER_IP)
    parser.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("--file", required=True, help="Gönderilecek dosyanın yolu")
    parser.add_argument("--packet-size", type=int, default=DEFAULT_PACKET_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--log-dir", default=LOGS_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    success = send_file(
        server_ip=args.server_ip,
        server_port=args.server_port,
        file_path=args.file,
        packet_size=args.packet_size,
        timeout=args.timeout,
        log_dir=args.log_dir,
    )
    if success:
        print("TCP aktarımı başarıyla tamamlandı.")
    else:
        raise SystemExit("TCP aktarımı başarısız oldu.")


if __name__ == "__main__":
    main()
