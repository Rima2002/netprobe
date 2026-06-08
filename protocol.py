"""NetProbe UDP protokolü için paket oluşturma ve çözme işlemleri.

Bu projede güvenilirlik mekanizması bilinçli olarak uygulama katmanında
kurulur. UDP yalnızca datagram taşır; bu modül bozuk paketleri tespit etmek,
alınan parçaları ACK ile onaylamak ve dosyayı doğru sırada yeniden oluşturmak
için kullanılan paket alanlarını tanımlar.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass


TYPE_DATA = 1
TYPE_ACK = 2
TYPE_START = 3
TYPE_FIN = 4
TYPE_FIN_ACK = 5
TYPE_ERROR = 6

TYPE_NAMES = {
    TYPE_DATA: "DATA",
    TYPE_ACK: "ACK",
    TYPE_START: "START",
    TYPE_FIN: "FIN",
    TYPE_FIN_ACK: "FIN_ACK",
    TYPE_ERROR: "ERROR",
}

# Header layout: packet_type, sequence_number, total_packets, payload_length, checksum.
HEADER_FORMAT = "!BIIH32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_UDP_PAYLOAD = 65507


@dataclass(frozen=True)
class Packet:
    packet_type: int
    sequence_number: int
    total_packets: int
    payload_length: int
    checksum: bytes
    payload: bytes


def checksum_payload(payload: bytes) -> bytes:
    """Bir paket payload alanı için SHA-256 özeti döndürür."""

    return hashlib.sha256(payload).digest()


def file_sha256(path: str) -> str:
    """Dosyanın tamamını belleğe almadan SHA-256 hash değerini hesaplar."""

    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for block in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_packet(
    packet_type: int,
    sequence_number: int,
    total_packets: int,
    payload: bytes = b"",
) -> bytes:
    """NetProbe başlık formatını kullanarak ikili UDP paketi oluşturur."""

    if len(payload) > MAX_UDP_PAYLOAD - HEADER_SIZE:
        raise ValueError("Payload is too large for one UDP datagram")

    checksum = checksum_payload(payload)
    header = struct.pack(
        HEADER_FORMAT,
        packet_type,
        sequence_number,
        total_packets,
        len(payload),
        checksum,
    )
    return header + payload


def parse_packet(raw_packet: bytes) -> Packet:
    """İkili paketi çözer ve bildirilen payload uzunluğunu doğrular."""

    if len(raw_packet) < HEADER_SIZE:
        raise ValueError("Packet is smaller than the protocol header")

    header = raw_packet[:HEADER_SIZE]
    payload = raw_packet[HEADER_SIZE:]
    packet_type, sequence_number, total_packets, payload_length, checksum = struct.unpack(
        HEADER_FORMAT, header
    )

    if payload_length != len(payload):
        raise ValueError("Header payload length does not match packet size")

    return Packet(
        packet_type=packet_type,
        sequence_number=sequence_number,
        total_packets=total_packets,
        payload_length=payload_length,
        checksum=checksum,
        payload=payload,
    )


def verify_packet(packet: Packet) -> bool:
    """Payload özeti başlıktaki checksum ile eşleşirse True döndürür."""

    return checksum_payload(packet.payload) == packet.checksum


def split_file(path: str, chunk_size: int) -> list[bytes]:
    """Dosyayı UDP payload alanına sığacak parçalara böler."""

    if chunk_size <= 0:
        raise ValueError("Packet size must be greater than zero")

    max_payload = MAX_UDP_PAYLOAD - HEADER_SIZE
    if chunk_size > max_payload:
        raise ValueError(f"Packet size must be at most {max_payload} bytes")

    chunks: list[bytes] = []
    with open(path, "rb") as file_obj:
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)

    return chunks


def build_start_payload(file_path: str, total_packets: int, file_hash: str, file_size: int) -> bytes:
    """START paketi için aktarım üst bilgisini encode eder."""

    filename = os.path.basename(file_path)
    return f"{filename}|{total_packets}|{file_hash}|{file_size}".encode("utf-8")


def parse_start_payload(payload: bytes) -> dict[str, str | int]:
    """İstemcinin gönderdiği aktarım üst bilgisini çözer."""

    text = payload.decode("utf-8")
    filename, total_packets, file_hash, file_size = text.split("|", 3)
    return {
        "filename": os.path.basename(filename),
        "total_packets": int(total_packets),
        "file_hash": file_hash,
        "file_size": int(file_size),
    }
