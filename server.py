"""UDP server for NetProbe reliable file transfer."""

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
    return loss_rate > 0 and random.random() < loss_rate


def send_ack(
    sock: socket.socket,
    address: tuple[str, int],
    ack_type: int,
    sequence_number: int,
    total_packets: int,
    logger: EventLogger,
    ack_loss_rate: float,
    ack_for: str,
) -> None:
    ack_name = TYPE_NAMES.get(ack_type, str(ack_type))
    if should_drop(ack_loss_rate):
        logger.log(
            event="simulated_ack_loss",
            packet_type=ack_name,
            sequence_number=sequence_number,
            details="Server intentionally skipped ACK send for experiment",
        )
        return

    sock.sendto(make_packet(ack_type, sequence_number, total_packets, ack_for.encode("ascii")), address)
    logger.log(event="ack_sent", packet_type=ack_name, sequence_number=sequence_number, details=f"ack_for={ack_for}")


def safe_received_path(output_dir: str, filename: str) -> str:
    clean_name = os.path.basename(filename) or "received_file.bin"
    return os.path.join(output_dir, clean_name)


def reconstruct_file(session: TransferSession, output_dir: str) -> tuple[str, str, bool]:
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
    os.makedirs(output_dir, exist_ok=True)
    logger = EventLogger(log_dir, prefix="server_transfer")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sessions: dict[tuple[str, int], TransferSession] = {}
    completed_fin_sequences: dict[tuple[str, int], tuple[int, int]] = {}

    print(f"NetProbe server listening on {host}:{port}")
    logger.log(event="server_started", details=f"host={host}; port={port}; ack_loss_rate={ack_loss_rate}")

    try:
        while True:
            raw_packet, client_address = sock.recvfrom(HEADER_SIZE + 65507)

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
                send_ack(sock, client_address, TYPE_ACK, packet.sequence_number, packet.total_packets, logger, ack_loss_rate, "START")
                continue

            session = sessions.get(client_address)
            if session is None:
                if packet.packet_type == TYPE_FIN and client_address in completed_fin_sequences:
                    fin_sequence, total_packets = completed_fin_sequences[client_address]
                    send_ack(sock, client_address, TYPE_FIN_ACK, fin_sequence, total_packets, logger, ack_loss_rate, "FIN")
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
                    details="Received DATA/FIN before START",
                )
                sock.sendto(make_packet(TYPE_ERROR, packet.sequence_number, packet.total_packets, b"missing START"), client_address)
                continue

            if packet.packet_type == TYPE_DATA:
                if packet.sequence_number in session.chunks:
                    session.duplicate_count += 1
                    logger.log(
                        event="duplicate_packet_ignored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        payload_bytes=packet.payload_length,
                    )
                elif packet.sequence_number >= session.total_packets:
                    logger.log(
                        event="out_of_range_packet_ignored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        details=f"total_packets={session.total_packets}",
                    )
                else:
                    session.chunks[packet.sequence_number] = packet.payload
                    logger.log(
                        event="chunk_stored",
                        packet_type=packet_name,
                        sequence_number=packet.sequence_number,
                        payload_bytes=packet.payload_length,
                        details=f"stored_chunks={len(session.chunks)}/{session.total_packets}",
                    )

                # Duplicate packets are ACKed again because the first ACK may
                # have been lost. This is the server half of Stop-and-Wait.
                send_ack(sock, client_address, TYPE_ACK, packet.sequence_number, packet.total_packets, logger, ack_loss_rate, "DATA")
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
                    details=(
                        f"path={output_path}; expected_hash={session.expected_hash}; "
                        f"actual_hash={actual_hash}; hash_ok={hash_ok}; "
                        f"duplicates={session.duplicate_count}; corrupted={session.corrupted_count}; "
                        f"elapsed={elapsed:.6f}"
                    ),
                )
                send_ack(sock, client_address, TYPE_FIN_ACK, packet.sequence_number, packet.total_packets, logger, ack_loss_rate, "FIN")
                completed_fin_sequences[client_address] = (packet.sequence_number, packet.total_packets)
                del sessions[client_address]
                if once:
                    return
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
    parser.add_argument("--once", action="store_true", help="Exit after one completed transfer")
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
