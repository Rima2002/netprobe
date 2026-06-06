import csv
import os
import tempfile
import unittest

from analyzer import analyze_log
from logger import FIELDNAMES


class AnalyzerTests(unittest.TestCase):
    def test_analyzer_metrics_from_sample_log(self):
        rows = [
            {
                "timestamp": 1.0,
                "event": "transfer_started",
                "packet_type": "",
                "sequence_number": "",
                "attempt": "",
                "payload_bytes": "",
                "rtt": "",
                "integrity_ok": "",
                "details": "",
            },
            {
                "timestamp": 1.1,
                "event": "packet_sent",
                "packet_type": "DATA",
                "sequence_number": 0,
                "attempt": 1,
                "payload_bytes": 100,
                "rtt": "",
                "integrity_ok": "",
                "details": "send_time=1.1",
            },
            {
                "timestamp": 1.2,
                "event": "ack_received",
                "packet_type": "ACK",
                "sequence_number": 0,
                "attempt": 1,
                "payload_bytes": 0,
                "rtt": 0.1,
                "integrity_ok": "",
                "details": "ack_for=DATA",
            },
            {
                "timestamp": 1.3,
                "event": "packet_sent",
                "packet_type": "DATA",
                "sequence_number": 1,
                "attempt": 1,
                "payload_bytes": 100,
                "rtt": "",
                "integrity_ok": "",
                "details": "send_time=1.3",
            },
            {
                "timestamp": 1.4,
                "event": "simulated_packet_loss",
                "packet_type": "DATA",
                "sequence_number": 1,
                "attempt": 2,
                "payload_bytes": 100,
                "rtt": "",
                "integrity_ok": "",
                "details": "send_time=1.4",
            },
            {
                "timestamp": 1.5,
                "event": "timeout",
                "packet_type": "DATA",
                "sequence_number": 1,
                "attempt": 2,
                "payload_bytes": 100,
                "rtt": "",
                "integrity_ok": "",
                "details": "timeout_value=1.0",
            },
            {
                "timestamp": 1.6,
                "event": "packet_sent",
                "packet_type": "DATA",
                "sequence_number": 1,
                "attempt": 3,
                "payload_bytes": 100,
                "rtt": "",
                "integrity_ok": "",
                "details": "send_time=1.6",
            },
            {
                "timestamp": 1.7,
                "event": "ack_received",
                "packet_type": "ACK",
                "sequence_number": 1,
                "attempt": 3,
                "payload_bytes": 0,
                "rtt": 0.2,
                "integrity_ok": "",
                "details": "ack_for=DATA",
            },
            {
                "timestamp": 3.0,
                "event": "transfer_completed",
                "packet_type": "",
                "sequence_number": "",
                "attempt": "",
                "payload_bytes": 200,
                "rtt": "",
                "integrity_ok": "true",
                "details": "original_file_size=200; total_transfer_time=2.0; integrity_ok=true",
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "client.csv")
            with open(log_path, "w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
                writer.writeheader()
                writer.writerows(rows)

            metrics = analyze_log(log_path)

        self.assertEqual(metrics["file_size"], 200)
        self.assertEqual(metrics["transferred_bytes"], 400)
        self.assertAlmostEqual(metrics["throughput"], 200.0)
        self.assertAlmostEqual(metrics["goodput"], 100.0)
        self.assertEqual(metrics["retransmission_count"], 2)
        self.assertAlmostEqual(metrics["packet_loss_rate"], 0.25)
        self.assertTrue(metrics["integrity_ok"])


if __name__ == "__main__":
    unittest.main()
