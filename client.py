"""NetProbe UDP istemcisi.

Bu dosya projenin ana akışını sade biçimde tutar:
dosyayı parçala, START metadata paketini gönder, DATA paketlerini
Stop-and-Wait ARQ ile aktar, FIN paketiyle SHA-256 doğrulamasını tamamla.
"""

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
    """Yapay paket kaybı simülasyonu için gönderimi atlayıp atlamayacağını döndürür."""

    return loss_rate > 0 and random.random() < loss_rate


def maybe_delay(delay_ms: float) -> None:
    """Deneylerde gecikme etkisini görmek için isteğe bağlı bekleme uygular."""

    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)


def parse_ack_details(ack_text: str) -> dict[str, str]:
    """ACK payload içindeki key=value alanlarını sözlüğe çevirir."""

    details: dict[str, str] = {}
    for part in ack_text.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        details[key.strip()] = value.strip()
    return details


def wait_for_matching_ack(
    sock: socket.socket,
    expected_ack_type: int,
    expected_sequence: int,
    expected_ack_for: str,
) -> tuple[float, str]:
    """Beklenen sequence number için doğru ACK paketini bekler."""

    while True:
        raw_ack, _ = sock.recvfrom(HEADER_SIZE + 1024)
        ack = parse_packet(raw_ack)

        if not verify_packet(ack):
            continue

        ack_text = ack.payload.decode("ascii", errors="replace")
        ack_for = ack_text.split(";", 1)[0]

        if (
            ack.packet_type == expected_ack_type
            and ack.sequence_number == expected_sequence
            and ack_for == expected_ack_for
        ):
            return time.time(), ack_text


def log_packet_send(
    logger: EventLogger,
    event: str,
    packet_name: str,
    sequence_number: int,
    attempt: int,
    payload_size: int,
    send_time: float,
    delay_ms: float,
) -> None:
    logger.log(
        event=event,
        packet_type=packet_name,
        sequence_number=sequence_number,
        attempt=attempt,
        payload_bytes=payload_size,
        details=f"send_time={send_time}; delay_ms={delay_ms}",
    )


def send_reliable_packet(
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
    delay_ms: float,
    logger: EventLogger,
) -> tuple[bool, int, dict[str, str]]:
    """Bir paketi Stop-and-Wait ARQ ile güvenilir şekilde gönderir.

    Her turda tek paket gönderilir ve aynı sequence number için ACK beklenir.
    ACK gelmezse timeout oluşur ve paket yeniden gönderilir.
    """

    packet = make_packet(packet_type, sequence_number, total_packets, payload)
    packet_name = TYPE_NAMES.get(packet_type, str(packet_type))
    ack_name = TYPE_NAMES.get(expected_ack_type, str(expected_ack_type))

    for attempt in range(1, max_retries + 2):
        send_time = time.time()
        maybe_delay(delay_ms)

        # Yapay kayıp varsa datagram gerçekten gönderilmez; bu deney amaçlıdır.
        if should_drop(loss_rate):
            logger.log(
                event="simulated_packet_loss",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempt,
                payload_bytes=len(payload),
                details=(
                    f"send_time={send_time}; "
                    "client_skipped_send_for_artificial_loss=True; "
                    f"delay_ms={delay_ms}"
                ),
            )
        else:
            sock.sendto(packet, server_address)
            log_packet_send(
                logger,
                "packet_sent",
                packet_name,
                sequence_number,
                attempt,
                len(payload),
                send_time,
                delay_ms,
            )

        try:
            ack_time, ack_text = wait_for_matching_ack(
                sock,
                expected_ack_type,
                sequence_number,
                packet_name,
            )
            ack_details = parse_ack_details(ack_text)
            logger.log(
                event="ack_received",
                packet_type=ack_name,
                sequence_number=sequence_number,
                attempt=attempt,
                payload_bytes=0,
                rtt=ack_time - send_time,
                integrity_ok=ack_details.get("integrity_ok", ""),
                details=f"ack_for={packet_name}; ack_receive_time={ack_time}; raw_ack_payload={ack_text}",
            )
            return True, attempt - 1, ack_details
        except socket.timeout:
            # Timeout, Stop-and-Wait içinde retransmission kararını tetikler.
            logger.log(
                event="timeout",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempt,
                payload_bytes=len(payload),
                details=f"{timeout} saniye içinde ACK gelmedi; timeout_value={timeout}",
            )
        except ConnectionResetError as exc:
            logger.log(
                event="timeout",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempt,
                payload_bytes=len(payload),
                details=f"ACK beklenirken UDP alma işlemi sıfırlandı; timeout kabul edildi; error={exc}",
            )
        except ValueError as exc:
            logger.log(
                event="invalid_ack",
                packet_type=packet_name,
                sequence_number=sequence_number,
                attempt=attempt,
                details=str(exc),
            )

    logger.log(
        event="packet_failed",
        packet_type=packet_name,
        sequence_number=sequence_number,
        attempt=max_retries + 1,
        payload_bytes=len(payload),
        details=f"Maksimum yeniden gönderim sayısı aşıldı: {max_retries}",
    )
    return False, max_retries + 1, {}


def send_metadata(
    sock: socket.socket,
    server_address: tuple[str, int],
    file_path: str,
    total_packets: int,
    file_hash: str,
    file_size: int,
    timeout: float,
    max_retries: int,
    loss_rate: float,
    delay_ms: float,
    logger: EventLogger,
) -> tuple[bool, int]:
    """START metadata paketini gönderir."""

    start_payload = build_start_payload(file_path, total_packets, file_hash, file_size)
    ok, retransmissions, _ = send_reliable_packet(
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
        delay_ms,
        logger,
    )
    return ok, retransmissions


def send_data_packets(
    sock: socket.socket,
    server_address: tuple[str, int],
    chunks: list[bytes],
    timeout: float,
    max_retries: int,
    loss_rate: float,
    delay_ms: float,
    logger: EventLogger,
) -> tuple[bool, int, int]:
    """Dosya parçalarını sequence number sırasıyla DATA paketi olarak gönderir."""

    total_packets = len(chunks)
    total_retransmissions = 0
    successful_packets = 0

    for sequence_number, chunk in enumerate(chunks):
        ok, retransmissions, _ = send_reliable_packet(
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
            delay_ms,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            return False, successful_packets, total_retransmissions
        successful_packets += 1

    return True, successful_packets, total_retransmissions


def finish_transfer(
    sock: socket.socket,
    server_address: tuple[str, int],
    total_packets: int,
    file_hash: str,
    timeout: float,
    max_retries: int,
    loss_rate: float,
    delay_ms: float,
    logger: EventLogger,
) -> tuple[bool, int, dict[str, str]]:
    """FIN paketini gönderir ve sunucunun bütünlük sonucunu alır."""

    return send_reliable_packet(
        sock,
        server_address,
        TYPE_FIN,
        total_packets,
        total_packets,
        file_hash.encode("ascii"),
        TYPE_FIN_ACK,
        timeout,
        max_retries,
        loss_rate,
        delay_ms,
        logger,
    )


def send_file(
    server_ip: str,
    server_port: int,
    file_path: str,
    packet_size: int,
    timeout: float,
    loss_rate: float,
    max_retries: int,
    log_dir: str,
    delay_ms: float = 0.0,
) -> bool:
    """Dosyayı UDP üzerinde Stop-and-Wait ARQ ile sunucuya aktarır."""

    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    logger = EventLogger(log_dir, prefix="client_transfer")
    server_address = (server_ip, server_port)

    chunks = split_file(file_path, packet_size)
    total_packets = len(chunks)
    file_hash = file_sha256(file_path)
    file_size = os.path.getsize(file_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start_time = time.time()

    successful_packets = 0
    failed_packets = 0
    total_retransmissions = 0

    logger.log(
        event="transfer_started",
        details=(
            f"server={server_ip}:{server_port}; file={file_path}; "
            f"size={file_size}; packet_size={packet_size}; timeout={timeout}; "
            f"loss_rate={loss_rate}; max_retries={max_retries}; "
            f"arq=stop-and-wait; delay_ms={delay_ms}"
        ),
    )

    try:
        ok, retransmissions = send_metadata(
            sock,
            server_address,
            file_path,
            total_packets,
            file_hash,
            file_size,
            timeout,
            max_retries,
            loss_rate,
            delay_ms,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            failed_packets += 1
            return False

        ok, successful_packets, retransmissions = send_data_packets(
            sock,
            server_address,
            chunks,
            timeout,
            max_retries,
            loss_rate,
            delay_ms,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            failed_packets += 1
            return False

        ok, retransmissions, fin_ack_details = finish_transfer(
            sock,
            server_address,
            total_packets,
            file_hash,
            timeout,
            max_retries,
            loss_rate,
            delay_ms,
            logger,
        )
        total_retransmissions += retransmissions
        if not ok:
            failed_packets += 1
            return False

        completion_time = time.time() - start_time
        integrity_ok = fin_ack_details.get("integrity_ok", "UNKNOWN")
        expected_hash = fin_ack_details.get("expected_hash", file_hash)
        actual_hash = fin_ack_details.get("actual_hash", "UNKNOWN")

        # Analyzer, throughput/goodput ve hata oranlarını bu kapanış kaydından çıkarır.
        logger.log(
            event="transfer_completed",
            payload_bytes=file_size,
            integrity_ok=integrity_ok,
            details=(
                f"successful_packet_count={successful_packets}; "
                f"failed_packet_count={failed_packets}; "
                f"total_retransmissions={total_retransmissions}; "
                f"original_file_size={file_size}; "
                f"transferred_bytes={file_size}; "
                f"total_transfer_time={completion_time:.6f}; "
                f"sha256={file_hash}; "
                f"expected_hash={expected_hash}; "
                f"actual_hash={actual_hash}; "
                f"integrity_ok={integrity_ok}"
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
    parser = argparse.ArgumentParser(description="NetProbe UDP Stop-and-Wait file transfer client")
    parser.add_argument("--server-ip", default=DEFAULT_SERVER_IP)
    parser.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("--file", required=True, help="Path of the file to send")
    parser.add_argument("--packet-size", type=int, default=DEFAULT_PACKET_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--loss-rate", type=float, default=DEFAULT_LOSS_RATE)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--delay-ms", type=float, default=0.0, help="Artificial delay before each packet")
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
        delay_ms=args.delay_ms,
    )
    if success:
        print("Transfer completed successfully.")
    else:
        raise SystemExit("Transfer failed.")


if __name__ == "__main__":
    main()
