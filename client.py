"""UDP client for NetProbe reliable file transfer."""

from __future__ import annotations

import argparse
import os
import random
import socket
import time

try:
    from .config import (
        DEFAULT_LOSS_RATE,
        DEFAULT_MAX_RETRIES,
        DEFAULT_PACKET_SIZE,
        DEFAULT_SERVER_IP,
        DEFAULT_SERVER_PORT,
        DEFAULT_TIMEOUT,
        LOGS_DIR,
    )
    from .logger import EventLogger
    from .protocol import (
        HEADER_SIZE,
        TYPE_ACK,
        TYPE_DATA,
        TYPE_FIN,
        TYPE_FIN_ACK,
        TYPE_NAMES,
        TYPE_START,
        build_start_payload,
        file_sha256,
        make_packet,
        parse_packet,
        split_file,
        verify_packet,
    )
except ImportError:
    from config import (
        DEFAULT_LOSS_RATE,
        DEFAULT_MAX_RETRIES,
        DEFAULT_PACKET_SIZE,
        DEFAULT_SERVER_IP,
        DEFAULT_SERVER_PORT,
        DEFAULT_TIMEOUT,
        LOGS_DIR,
    )
    from logger import EventLogger
    from protocol import (
        HEADER_SIZE,
        TYPE_ACK,
        TYPE_DATA,
        TYPE_FIN,
        TYPE_FIN_ACK,
        TYPE_NAMES,
        TYPE_START,
        build_start_payload,
        file_sha256,
        make_packet,
        parse_packet,
        split_file,
        verify_packet,
    )


def should_drop(loss_rate: float) -> bool:
    """Return True when artificial client-side packet loss should be simulated."""

    return loss_rate > 0 and random.random() < loss_rate


def wait_for_ack(
    sock: socket.socket,
    expected_type: int,
    expected_sequence: int,
    expected_payload: bytes,
) -> float | None:
    """Wait for a valid ACK and return RTT timestamp base time handled by caller."""

    while True:
        raw_ack, _ = sock.recvfrom(HEADER_SIZE + 1024)
        ack = parse_packet(raw_ack)

        if not verify_packet(ack):
            continue

        if (
            ack.packet_type == expected_type
            and ack.sequence_number == expected_sequence
            and ack.payload == expected_payload
        ):
            return time.time()


def send_with_stop_and_wait(
    sock: socket.socket,
    server_address: tuple[str, int],
    packet_type: int,
    sequence_number: int,
    total_packets: int,
    payload: bytes,
    expected_ack_type: int,
    timeout: float,
    max_retries: int,
    loss_rate: float,
    logger: EventLogger,
) -> tuple[bool, int, float | None]:
    """Send one packet until its ACK arrives or retry budget is exhausted.

    Stop-and-Wait means exactly one unacknowledged packet exists at a time.
    If the ACK is missing after the timeout, the client retransmits the same
    sequence number, allowing the server to detect duplicates and ACK them.
    """

    encoded_packet = make_packet(packet_type, sequence_number, total_packets, payload)
    packet_name = TYPE_NAMES.get(packet_type, str(packet_type))
    ack_name = TYPE_NAMES.get(expected_ack_type, str(expected_ack_type))
    attempts = 0

    while attempts <= max_retries:
        attempts += 1
        send_time = time.time()

        if should_drop(loss_rate):
            logger.log(
                event="simulated_packet_loss",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempts,
                payload_bytes=len(payload),
                details=f"send_time={send_time}; client_skipped_send_for_artificial_loss=True",
            )
        else:
            sock.sendto(encoded_packet, server_address)
            logger.log(
                event="packet_sent",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempts,
                payload_bytes=len(payload),
                details=f"send_time={send_time}",
            )

        try:
            ack_time = wait_for_ack(sock, expected_ack_type, sequence_number, packet_name.encode("ascii"))
            rtt = ack_time - send_time if ack_time is not None else None
            ack_for = packet_name
            logger.log(
                event="ack_received",
                packet_type=ack_name,
                sequence_number=sequence_number,
                attempt=attempts,
                payload_bytes=0,
                rtt=rtt if rtt is not None else "",
                details=f"ack_for={ack_for}; ack_receive_time={ack_time}",
            )
            return True, attempts - 1, rtt
        except socket.timeout:
            logger.log(
                event="timeout",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempts,
                payload_bytes=len(payload),
                details=f"No ACK within {timeout} seconds; timeout_value={timeout}",
            )
        except ConnectionResetError as exc:
            logger.log(
                event="timeout",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempts,
                payload_bytes=len(payload),
                details=f"UDP receive reset while waiting for ACK; treated as timeout; error={exc}",
            )
        except ValueError as exc:
            logger.log(
                event="invalid_ack",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempts,
                details=str(exc),
            )

    logger.log(
        event="packet_failed",
        packet_type=packet_name,
        sequence_number=sequence_number,
        attempt=attempts,
        payload_bytes=len(payload),
        details=f"Exceeded maximum retransmission count: {max_retries}",
    )
    return False, attempts - 1, None


def send_file(
    server_ip: str,
    server_port: int,
    file_path: str,
    packet_size: int,
    timeout: float,
    loss_rate: float,
    max_retries: int,
    log_dir: str,
) -> bool:
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    logger = EventLogger(log_dir, prefix="client_transfer")
    server_address = (server_ip, server_port)
    chunks = split_file(file_path, packet_size)
    total_packets = len(chunks)
    file_hash = file_sha256(file_path)
    file_size = os.path.getsize(file_path)
    start_payload = build_start_payload(file_path, total_packets, file_hash, file_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    successful_packets = 0
    failed_packets = 0
    total_retransmissions = 0
    start_time = time.time()

    logger.log(
        event="transfer_started",
        details=(
            f"server={server_ip}:{server_port}; file={file_path}; "
            f"size={file_size}; packet_size={packet_size}; timeout={timeout}; "
            f"loss_rate={loss_rate}; max_retries={max_retries}"
        ),
    )

    try:
        ok, retransmissions, _ = send_with_stop_and_wait(
            sock,
            server_address,
            TYPE_START,
            0,
            total_packets,
            start_payload,
            TYPE_ACK,
            timeout,
            max_retries,
            loss_rate,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            failed_packets += 1
            return False

        for sequence_number, chunk in enumerate(chunks):
            ok, retransmissions, _ = send_with_stop_and_wait(
                sock,
                server_address,
                TYPE_DATA,
                sequence_number,
                total_packets,
                chunk,
                TYPE_ACK,
                timeout,
                max_retries,
                loss_rate,
                logger,
            )
            total_retransmissions += retransmissions
            if not ok:
                failed_packets += 1
                return False
            successful_packets += 1

        fin_payload = file_hash.encode("ascii")
        ok, retransmissions, _ = send_with_stop_and_wait(
            sock,
            server_address,
            TYPE_FIN,
            total_packets,
            total_packets,
            fin_payload,
            TYPE_FIN_ACK,
            timeout,
            max_retries,
            loss_rate,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            failed_packets += 1
            return False

        completion_time = time.time() - start_time
        logger.log(
            event="transfer_completed",
            payload_bytes=file_size,
            details=(
                f"successful_packet_count={successful_packets}; "
                f"failed_packet_count={failed_packets}; "
                f"total_retransmissions={total_retransmissions}; "
                f"original_file_size={file_size}; "
                f"transferred_bytes={file_size}; "
                f"total_transfer_time={completion_time:.6f}; "
                f"sha256={file_hash}"
            ),
        )
        return True
    finally:
        completion_time = time.time() - start_time
        logger.log(
            event="transfer_finished",
            payload_bytes=file_size,
            details=f"elapsed={completion_time:.6f}; total_packets={total_packets}",
        )
        csv_path, json_path = logger.save()
        sock.close()
        print(f"Logs saved: {csv_path} and {json_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetProbe UDP file transfer client")
    parser.add_argument("--server-ip", default=DEFAULT_SERVER_IP)
    parser.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("--file", required=True, help="Path of the file to send")
    parser.add_argument("--packet-size", type=int, default=DEFAULT_PACKET_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--loss-rate", type=float, default=DEFAULT_LOSS_RATE)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
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
        loss_rate=args.loss_rate,
        max_retries=args.max_retries,
        log_dir=args.log_dir,
    )
    if success:
        print("Transfer completed successfully.")
    else:
        raise SystemExit("Transfer failed.")


if __name__ == "__main__":
    main()
