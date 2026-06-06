import os
import tempfile
import unittest

from protocol import (
    TYPE_ACK,
    TYPE_DATA,
    checksum_payload,
    file_sha256,
    make_packet,
    parse_packet,
    verify_packet,
)


class ProtocolTests(unittest.TestCase):
    def test_checksum_is_stable_for_same_payload(self):
        payload = b"netprobe-test"
        self.assertEqual(checksum_payload(payload), checksum_payload(payload))

    def test_data_packet_create_parse_and_verify(self):
        raw = make_packet(TYPE_DATA, 7, 10, b"chunk")
        packet = parse_packet(raw)

        self.assertEqual(packet.packet_type, TYPE_DATA)
        self.assertEqual(packet.sequence_number, 7)
        self.assertEqual(packet.total_packets, 10)
        self.assertEqual(packet.payload, b"chunk")
        self.assertTrue(verify_packet(packet))

    def test_ack_packet_create_parse_and_verify(self):
        raw = make_packet(TYPE_ACK, 3, 5, b"DATA")
        packet = parse_packet(raw)

        self.assertEqual(packet.packet_type, TYPE_ACK)
        self.assertEqual(packet.sequence_number, 3)
        self.assertEqual(packet.payload, b"DATA")
        self.assertTrue(verify_packet(packet))

    def test_sha256_same_file_is_same_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "sample.bin")
            with open(path, "wb") as file_obj:
                file_obj.write(b"same-content")

            self.assertEqual(file_sha256(path), file_sha256(path))


if __name__ == "__main__":
    unittest.main()
