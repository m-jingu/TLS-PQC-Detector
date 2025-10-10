# TLS PQC Detector

TLS PQC (Post-Quantum Cryptography) detection tool for pcap/pcapng files.
Detects TLS ServerHello and ClientHello packets and analyzes PQC algorithm usage.

## Features

- **Dual-mode analysis**: ServerHello and ClientHello packet detection
- **Optimized streaming processing** with parallel execution
- **Support for TLS 1.2 and TLS 1.3** analysis
- **PQC NamedGroup detection** (x25519_kyber768_draft00, mlkem768, etc.)
- **ClientHello PQC proposal analysis** (Supported Groups, Key Share, Signature Algorithms)
- **Comprehensive statistics** and automatic file output
- **Timestamp-based result organization**

## Detection Logic

- **TLS 1.2**: Always classified as classical (no PQC)
- **TLS 1.3**: Analyzes key_share NamedGroup for PQC algorithms
- **PQC NamedGroups**: 0xFE30, 0xFE31, 0xFE32, 0xFE34
- **ClientHello**: Analyzes supported_groups, key_share_groups, signature_algorithms

## Usage

```bash
python tls_pqc_detector.py input.pcap [options]
```

### Options

- `--mode {server,client,both}` - Analysis mode (default: both)
- `--workers N` - Number of parallel workers (default: 8)
- `--chunk-size N` - Chunk size for processing (default: 1000)
- `--buffer-size N` - Buffer size for packet queue (default: 20000)
- `--no-progress` - Disable progress output

### Examples

```bash
# Default: Both ServerHello and ClientHello analysis
python tls_pqc_detector.py capture.pcap

# ServerHello analysis only
python tls_pqc_detector.py capture.pcap --mode server

# ClientHello analysis only
python tls_pqc_detector.py capture.pcap --mode client

# High-performance processing
python tls_pqc_detector.py capture.pcap --workers 16 --chunk-size 2000
```

## Output

Results are automatically saved to `results/YYYYMMDD_HHMMSS/` directory:

- **JSON files**: `server_results.json`, `client_results.json`
- **Table files**: `server_results.txt`, `client_results.txt`
- **Summary files**: `server_summary.txt`, `client_summary.txt`
- **Statistics**: Displayed to stdout

## Performance

- Optimized for large pcap files with streaming processing
- Configurable parallelization and memory usage
- Real-time progress monitoring with speed metrics
- Default: 8 workers, 1000 chunk size for optimal performance

## Requirements

- pyshark
- Python 3.7+

## Installation

```bash
pip install pyshark
```