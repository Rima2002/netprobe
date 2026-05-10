# NetProbe

NetProbe is a UDP-based reliable file transfer, traffic monitoring, and network performance analysis platform. It uses raw Python UDP sockets and implements reliability manually at the application layer with Stop-and-Wait ARQ.

GitHub: `https://github.com/Rima2002/netprobe`

## Project Structure

```text
netprobe/
  client.py
  server.py
  protocol.py
  logger.py
  analyzer.py
  experiments.py
  config.py
  requirements.txt
  test_files/
  received_files/
  logs/
  results/
```

## Dependencies

Install dependencies from the `netprobe` folder:

```cmd
python -m pip install -r requirements.txt
```

If `python` is not on PATH in Windows cmd, use:

```cmd
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -m pip install -r requirements.txt
```

## Reliability Mechanism

NetProbe sends a file as numbered UDP chunks. Each DATA packet contains a packet type, sequence number, total packet count, payload length, checksum, and payload.

The client sends one packet and waits for the matching ACK before sending the next packet. If no ACK arrives before the timeout, the same sequence number is retransmitted. After the retry limit is exceeded, the transfer fails.

The server verifies each packet checksum, stores each valid DATA chunk by sequence number, ignores duplicate DATA packets, and resends the correct ACK for duplicates. At the end, the server reconstructs the file in order and verifies the final SHA-256 hash.

## Run Server

Terminal 1:

```cmd
cd "C:\Users\Rima Farah Eleuch\OneDrive\Desktop\SPRING SEMESTER 2026\BilgisayarAglari_1\Proje\netprobe"
python server.py --host 127.0.0.1 --port 5005 --once
```

With explicit Python path:

```cmd
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" server.py --host 127.0.0.1 --port 5005 --once
```

To make duplicate-packet handling visible, intentionally lose some ACKs:

```cmd
python server.py --host 127.0.0.1 --port 5005 --once --ack-loss-rate 0.2
```

## Run Client

Terminal 2:

```cmd
cd "C:\Users\Rima Farah Eleuch\OneDrive\Desktop\SPRING SEMESTER 2026\BilgisayarAglari_1\Proje\netprobe"
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files\medium.bin
```

With configurable values:

```cmd
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files\medium.bin --packet-size 1024 --timeout 1.0 --loss-rate 0.1 --max-retries 5
```

## Verify SHA-256

After a transfer:

```cmd
certutil -hashfile test_files\medium.bin SHA256
certutil -hashfile received_files\medium.bin SHA256
```

The two hashes must match.

## Analyze Logs

Use the newest client log from `logs/`:

```cmd
dir logs
python analyzer.py --log logs\client_transfer_YYYYMMDD_HHMMSS_mmm.csv
```

The analyzer saves:

```text
results/analysis_summary.csv
results/analysis_summary.json
```

Metrics include throughput, goodput, packet loss rate, retransmission count, retransmission rate, average RTT, completion time, duplicate count when analyzing server logs, transferred bytes, original file size, and integrity status when available.

## Run Experiments

The experiment script generates stronger files automatically:

```text
test_files/small.bin   >= 10 KB
test_files/medium.bin  >= 1 MB
test_files/large.bin   >= 10 MB
```

Run:

```cmd
python experiments.py
```

It writes:

```text
results/experiment_results.csv
```

The CSV includes:

```text
scenario, packet_size, timeout, loss_rate, file_size, throughput, goodput,
completion_time, retransmission_count, retransmission_rate, packet_loss_rate,
average_rtt, duplicate_count, integrity_ok
```

Graphs generated:

```text
results/packet_size_throughput_goodput.png
results/packet_size_completion_time.png
results/timeout_retransmission_count.png
results/timeout_completion_time.png
results/loss_rate_throughput_goodput.png
results/loss_rate_retransmission_rate.png
```

## Compliance Notes

- No ready-made file transfer library is used.
- UDP sockets are used directly through Python `socket`.
- Reliability is implemented manually with sequence numbers, ACKs, timeout, retransmission, duplicate detection, and SHA-256 verification.
- Helper libraries are limited to standard modules plus `pandas` and `matplotlib` for analysis and graphs.

