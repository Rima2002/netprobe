import unittest

from server import TransferSession, store_chunk_if_new


class ServerDuplicateTests(unittest.TestCase):
    def test_duplicate_packet_is_not_stored_twice(self):
        session = TransferSession(
            client_address=("127.0.0.1", 5005),
            filename="file.bin",
            total_packets=2,
            expected_hash="hash",
            expected_size=8,
        )

        self.assertEqual(store_chunk_if_new(session, 0, b"abcd"), "stored")
        self.assertEqual(store_chunk_if_new(session, 0, b"changed"), "duplicate")
        self.assertEqual(session.chunks[0], b"abcd")
        self.assertEqual(session.duplicate_count, 1)

    def test_out_of_range_packet_is_ignored(self):
        session = TransferSession(
            client_address=("127.0.0.1", 5005),
            filename="file.bin",
            total_packets=1,
            expected_hash="hash",
            expected_size=4,
        )

        self.assertEqual(store_chunk_if_new(session, 3, b"bad"), "out_of_range")
        self.assertEqual(session.chunks, {})


if __name__ == "__main__":
    unittest.main()
