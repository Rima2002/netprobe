"""NetProbe güvenilir dosya aktarımı için UDP sunucusu."""

from __future__ import annotations

import argparse
import os
import random
import socket
import time
from dataclasses import dataclass, field

try:
    from .config import DEFAULT_LOSS_RATE, DEFAULT_SERVER_PORT, LOGS_DIR, RECEIVED_FILES_DIR
    from .logger import EventLogger
    from .protocol import (
        HEADER_SIZE,
        TYPE_ACK,
        TYPE_DATA,
        TYPE_ERROR,
        TYPE_FIN,
        TYPE_FIN_ACK,
        TYPE_NAMES,
        TYPE_START,
        file_sha256,
        make_packet,
        parse_packet,
        parse_start_payload,
        verify_packet,
    )
except ImportError:
    from config import DEFAULT_LOSS_RATE, DEFAULT_SERVER_PORT, LOGS_DIR, RECEIVED_FILES_DIR
    from logger import EventLogger
    from protocol import (
        HEADER_SIZE,
        TYPE_ACK,
        TYPE_DATA,
        TYPE_ERROR,
        TYPE_FIN,
        TYPE_FIN_ACK,
        TYPE_NAMES,
        TYPE_START,
        file_sha256,
        make_packet,
        parse_packet,
        parse_start_payload,
        verify_packet,
    )


@dataclass
class TransferSession:
    client_address: tuple[str, int]
    filename: str
    total_packets: int
    expected_hash: str
    expected_size: int
    started_at: float = field(default_factory=time.time)
    chunks: dict[int, bytes] = field(default_factory=dict)
    duplicate_count: int = 0
    corrupted_count: int = 0


def should_drop(loss_rate: float) -> bool:
    """ACK kaybı deneylerinde gönderimi atlayıp atlamayacağını döndürür."""

    return loss_rate > 0 and random.random() < loss_rate


def store_chunk_if_new(session: TransferSession, sequence_number: int, payload: bytes) -> str:
    """DATA paketini yalnızca ilk kez geldiyse saklar."""

    if sequence_number in session.chunks:
        session.duplicate_count += 1
        return "duplicate"
    if sequence_number >= session.total_packets:
        return "out_of_range"

    session.chunks[sequence_number] = payload
    return "stored"


def send_ack(
    sock: socket.socket,
    address: tuple[str, int],
    ack_type: int,
    sequence_number: int,
    total_packets: int,
    logger: EventLogger,
    ack_loss_rate: float,
    ack_for: str,
    extra_details: dict[str, str | bool | int | float] | None = None,
) -> None:
    ack_name = TYPE_NAMES.get(ack_type, str(ack_type))
    extra_details = extra_details or {}
    if should_drop(ack_loss_rate):
        logger.log(
            event="simulated_ack_loss",
            packet_type=ack_name,
            sequence_number=sequence_number,
            details="Sunucu deney için ACK gönderimini bilinçli olarak atladı",
        )
        return

    payload_parts = [ack_for]
    payload_parts.extend(f"{key}={value}" for key, value in extra_details.items())
    payload = ";".join(payload_parts).encode("ascii")
    details = f"ack_for={ack_for}"
    if extra_details:
        details = "; ".join([details, *(f"{key}={value}" for key, value in extra_details.items())])

    sock.sendto(make_packet(ack_type, sequence_number, total_packets, payload), address)
    logger.log(
        event="ack_sent",
        packet_type=ack_name,
        sequence_number=sequence_number,
        integrity_ok=extra_details.get("integrity_ok", ""),
        details=details,
    )


def safe_received_path(output_dir: str, filename: str) -> str:
    """İstemciden gelen dosya adını dizin kaçışına izin vermeden hedef yola çevirir."""

    clean_name = os.path.basename(filename) or "received_file.bin"
    return os.path.join(output_dir, clean_name)


def reconstruct_file(session: TransferSession, output_dir: str) -> tuple[str, str, bool]:
    """Alınan DATA parçalarını sırayla yazar ve SHA-256 bütünlüğünü doğrular."""

    os.makedirs(output_dir, exist_ok=True)
    output_path = safe_received_path(output_dir, session.filename)

    with open(output_path, "wb") as output_file:
        for sequence_number in range(session.total_packets):
            output_file.write(session.chunks[sequence_number])

    actual_hash = file_sha256(output_path)
    return output_path, actual_hash, actual_hash == session.expected_hash


def run_server(
    host: str,
    port: int,
    output_dir: str,
    log_dir: str,
    ack_loss_rate: float,
    once: bool,
) -> None:
    """UDP sunucusunu çalıştırır ve her istemci aktarımını ayrı oturum olarak izler."""

    os.makedirs(output_dir, exist_ok=True)
    logger = EventLogger(log_dir, prefix="server_transfer")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sessions: dict[tuple[str, int], TransferSession] = {}
    completed_fin_sequences: dict[tuple[str, int], tuple[int, int]] = {}
    shutdown_deadline: float | None = None

    print(f"NetProbe UDP server listening on {host}:{port}")
    logger.log(event="server_started", details=f"host={host}; port={port}; ack_loss_rate={ack_loss_rate}")

    try:
        while True:
            if shutdown_deadline is not None:
                remaining = shutdown_deadline - time.time()
                if remaining <= 0:
                    return
                sock.settimeout(min(0.2, remaining))
            else:
                sock.settimeout(None)

            try:
                raw_packet, client_address = sock.recvfrom(HEADER_SIZE + 65507)
            except socket.timeout:
                continue

            try:
                packet = parse_packet(raw_packet)
            except ValueError as exc:
                logger.log(event="invalid_packet", details=str(exc))
                continue

            packet_name = TYPE_NAMES.get(packet.packet_type, str(packet.packet_type))
            logger.log(
                event="packet_received",
                packet_type=packet_name,
                sequence_number=packet.sequence_number,
                payload_bytes=packet.payload_length,
            )

            if not verify_packet(packet):
                logger.log(
                    event="checksum_failed",
                    packet_type=packet_name,
                    sequence_number=packet.sequence_number,
                    payload_bytes=packet.payload_length,
                )
                if client_address in sessions:
                    sessions[client_address].corrupted_count += 1
                continue

            if packet.packet_type == TYPE_START:
                metadata = parse_start_payload(packet.payload)
                session = TransferSession(
                    client_address=client_address,
                    filename=str(metadata["filename"]),
                    total_packets=int(metadata["total_packets"]),
                    expected_hash=str(metadata["file_hash"]),
                    expected_size=int(metadata["file_size"]),
                )
                sessions[client_address] = session
                logger.log(
                    event="transfer_metadata_received",
                    packet_type=packet_name,
                    sequence_number=packet.sequence_number,
                    details=(
                        f"filename={session.filename}; total_packets={session.total_packets}; "
                        f"expected_size={session.expected_size}; expected_hash={session.expected_hash}"
                    ),
                )
                send_ack(
                    sock,
                    client_address,
                    TYPE_ACK,
                    packet.sequence_number,
                    packet.total_packets,
                    logger,
                    ack_loss_rate,
                    "START",
                )
                continue

            session = sessions.get(client_address)
            if session is None:
                if packet.packet_type == TYPE_FIN and client_address in completed_fin_sequences:
                    fin_sequence, total_packets = completed_fin_sequences[client_address]
                    send_ack(
                        sock,
                        client_address,
                        TYPE_FIN_ACK,
                        fin_sequence,
                        total_packets,
                        logger,
                        ack_loss_rate,
                        "FIN",
                    )
                    logger.log(
                        event="duplicate_fin_reacknowledged",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                    )
                    continue

                logger.log(
                    event="unknown_session",
                    packet_type=packet_name,
                    sequence_number=packet.sequence_number,
                    details="START paketinden önce DATA/FIN alındı",
                )
                sock.sendto(
                    make_packet(TYPE_ERROR, packet.sequence_number, packet.total_packets, b"missing START"),
                    client_address,
                )
                continue

            if packet.packet_type == TYPE_DATA:
                store_status = store_chunk_if_new(session, packet.sequence_number, packet.payload)
                if store_status == "duplicate":
                    logger.log(
                        event="duplicate_packet_ignored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        payload_bytes=packet.payload_length,
                        details=(
                            "Duplicate DATA paketi tekrar saklanmadı; "
                            f"duplicate_count={session.duplicate_count}"
                        ),
                    )
                elif store_status == "out_of_range":
                    logger.log(
                        event="out_of_range_packet_ignored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        details=f"total_packets={session.total_packets}",
                    )
                else:
                    logger.log(
                        event="chunk_stored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        payload_bytes=packet.payload_length,
                        details=f"stored_chunks={len(session.chunks)}/{session.total_packets}",
                    )

                # ACK kaybı durumunda istemci aynı DATA paketini tekrar gönderebilir.
                send_ack(
                    sock,
                    client_address,
                    TYPE_ACK,
                    packet.sequence_number,
                    packet.total_packets,
                    logger,
                    ack_loss_rate,
                    "DATA",
                )
                continue

            if packet.packet_type == TYPE_FIN:
                missing = [seq for seq in range(session.total_packets) if seq not in session.chunks]
                if missing:
                    logger.log(
                        event="transfer_incomplete",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        details=f"missing_sequences={missing[:20]}",
                    )
                    continue

                output_path, actual_hash, hash_ok = reconstruct_file(session, output_dir)
                elapsed = time.time() - session.started_at
                logger.log(
                    event="file_reconstructed",
                    packet_type=packet_name,
                    sequence_number=packet.sequence_number,
                    payload_bytes=session.expected_size,
                    integrity_ok=hash_ok,
                    details=(
                        f"path={output_path}; expected_hash={session.expected_hash}; "
                        f"actual_hash={actual_hash}; integrity_ok={hash_ok}; "
                        f"duplicate_count={session.duplicate_count}; corrupted_count={session.corrupted_count}; "
                        f"original_file_size={session.expected_size}; transferred_bytes={session.expected_size}; "
                        f"total_transfer_time={elapsed:.6f}"
                    ),
                )
                send_ack(
                    sock,
                    client_address,
                    TYPE_FIN_ACK,
                    packet.sequence_number,
                    packet.total_packets,
                    logger,
                    ack_loss_rate,
                    "FIN",
                    {
                        "integrity_ok": str(hash_ok).lower(),
                        "expected_hash": session.expected_hash,
                        "actual_hash": actual_hash,
                    },
                )
                completed_fin_sequences[client_address] = (packet.sequence_number, packet.total_packets)
                del sessions[client_address]
                if once:
                    # FIN_ACK kaybı olursa istemcinin son FIN tekrarına cevap verebilmek için kısa süre beklenir.
                    shutdown_deadline = time.time() + 2.0
                    continue
    finally:
        csv_path, json_path = logger.save()
        sock.close()
        print(f"Server logs saved: {csv_path} and {json_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetProbe UDP file transfer server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("--output-dir", default=RECEIVED_FILES_DIR)
    parser.add_argument("--log-dir", default=LOGS_DIR)
    parser.add_argument("--ack-loss-rate", type=float, default=DEFAULT_LOSS_RATE)
    parser.add_argument("--once", action="store_true", help="Exit after one successful transfer")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_server(
        host=args.host,
        port=args.port,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
        ack_loss_rate=args.ack_loss_rate,
        once=args.once,
    )


if __name__ == "__main__":
    main()
