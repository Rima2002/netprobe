# NetProbe

NetProbe is a UDP-based reliable file transfer, traffic monitoring, and network performance analysis platform written in Python. It does not use a ready-made file transfer library. Reliability is implemented manually at the application layer with Stop-and-Wait ARQ.

Repository owner target: `https://github.com/Rima2002`

## Project Structure

```text
netprobe/
  client.py          UDP client, chunk sender, ACK wait, timeout, retransmission
  server.py          UDP server, checksum validation, duplicate filtering, reconstruction
  protocol.py        Packet format, encoding/decoding, checksum, SHA-256 helpers
  logger.py          CSV and JSON event logger
  analyzer.py        Metric calculation and graph generation
  experiments.py     Automated local experiment runner
  config.py          Default configuration values
  README.md
  requirements.txt
  test_files/        Input files for transfers and experiments
  received_files/    Files reconstructed by the server
  logs/              Client/server CSV and JSON logs
  results/           Analysis summaries and graphs
```

## Dependencies

Python 3.10+ is recommended.

Install the graph and analysis dependencies:

```bash
pip install -r requirements.txt
```

On Windows, if `python` opens the Microsoft Store instead of running Python, install Python from `python.org` or disable the Windows App Execution Alias for `python.exe`.

The transfer protocol itself uses direct UDP socket programming plus standard helper modules such as `socket`, `time`, `struct`, `hashlib`, `argparse`, `random`, `csv`, and `json`.

## Packet Format

Every UDP packet contains:

```text
packet type | sequence number | total packet count | payload length | checksum | payload
```

The header is packed with Python `struct` using this format:

```text
!BIIH32s
```

The checksum is a SHA-256 digest of the packet payload. The final reconstructed file is also verified with SHA-256.

## Reliability Mechanism

NetProbe uses Stop-and-Wait ARQ:

1. The client sends one packet.
2. The client waits for the matching ACK.
3. If the ACK arrives before timeout, the client sends the next packet.
4. If timeout occurs, the client retransmits the same packet.
5. By default, one packet can be retransmitted up to 5 times.
6. The server ignores duplicate DATA packets but sends ACK again, because the original ACK may have been lost.
7. The server stores chunks by sequence number and reconstructs the file in correct order after receiving `FIN`.

The code is organized so a Sliding Window design can be added later by replacing the client send loop while keeping the protocol and logging modules.

## Run The Server

From the `netprobe/` directory:

```bash
python server.py --host 0.0.0.0 --port 5005
```

For one transfer only:

```bash
python server.py --host 127.0.0.1 --port 5005 --once
```

From the parent directory:

```bash
python -m netprobe.server --host 0.0.0.0 --port 5005
```

## Run The Client

Open another terminal and run:

```bash
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/sample.txt
```

With configurable transfer parameters in PowerShell:

```powershell
python client.py ^
  --server-ip 127.0.0.1 ^
  --server-port 5005 ^
  --file test_files/sample.txt ^
  --packet-size 1024 ^
  --timeout 1.0 ^
  --loss-rate 0.1 ^
  --max-retries 5
```

PowerShell single-line version:

```powershell
python client.py --server-ip 127.0.0.1 --server-port 5005 --file test_files/sample.txt --packet-size 1024 --timeout 1.0 --loss-rate 0.1 --max-retries 5
```

## Logs

Each run saves CSV and JSON logs in `logs/`.

Logged events include:

- packet send time
- ACK receive time
- timeout events
- retransmissions
- successful packet count
- failed packet count
- total transfer time
- checksum and file integrity details

## Analyze One Transfer

Use the client CSV log:

```bash
python analyzer.py --log logs/client_transfer_YYYYMMDD_HHMMSS.csv
```

This calculates:

- throughput
- goodput
- packet loss rate
- retransmission count
- retransmission rate
- average RTT
- completion time

Summaries are written to `results/analysis_summary.csv` and `results/analysis_summary.json`.

## Run Experiments

The experiment runner starts a local server and client automatically for each scenario:

```bash
python experiments.py
```

It tests:

- different packet sizes: `512`, `1024`, `2048`
- different timeout values: `0.2`, `0.5`, `1.0`
- different artificial loss rates: `0.0`, `0.1`, `0.2`

Outputs:

```text
results/experiment_results.csv
results/packet_size_results.png
results/timeout_results.png
results/loss_rate_results.png
```

## Generate Graphs From Existing Experiment Results

```bash
python analyzer.py --results-csv results/experiment_results.csv
```

## Example GitHub Upload Flow

From the directory that contains `netprobe/`:

```bash
git init
git add netprobe
git commit -m "Add NetProbe UDP reliable file transfer project"
git branch -M main
git remote add origin https://github.com/Rima2002/netprobe.git
git push -u origin main
```
