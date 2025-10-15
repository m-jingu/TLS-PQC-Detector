# TLS PQC Detector

TLS PQC (Post-Quantum Cryptography) detection tool for pcap/pcapng files.
Detects TLS ServerHello and ClientHello packets and analyzes PQC algorithm usage.

## Features

- **Dual-mode analysis**: ServerHello and ClientHello packet detection
- **Optimized streaming processing** with parallel execution
- **Multiple pcap file support** with parallel processing
- **Large-scale batch processing** (up to 10,000 pcap files)
- **Frame number offset management** to avoid duplicates across files
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
python tls_pqc_detector.py input [options]
```

### Input Types

- **Single file**: `python tls_pqc_detector.py file.pcap`
- **Directory**: `python tls_pqc_detector.py pcap_directory/`
- **Wildcard**: `python tls_pqc_detector.py "*.pcap"`

### Options

- `--mode {server,client,both}` - Analysis mode (default: both)
- `--workers N` - Number of parallel workers per file (default: 8)
- `--processes N` - Number of parallel processes for multiple files (default: CPU count)
- `--chunk-size N` - Chunk size for processing (default: 1000)
- `--buffer-size N` - Buffer size for packet queue (default: 20000)
- `--no-progress` - Disable progress output

### Examples

```bash
# Single file analysis
python tls_pqc_detector.py capture.pcap

# Multiple files in directory
python tls_pqc_detector.py pcap_files/

# ServerHello analysis only
python tls_pqc_detector.py capture.pcap --mode server

# ClientHello analysis only
python tls_pqc_detector.py capture.pcap --mode client

# High-performance processing with custom settings
python tls_pqc_detector.py pcap_files/ --workers 16 --processes 8 --chunk-size 2000

# Large-scale batch processing
python tls_pqc_detector.py large_pcap_directory/ --processes 16
```

## Output

Results are automatically saved to `results/YYYYMMDD_HHMMSS/` directory:

- **JSON files**: `server_results.json`, `client_results.json`
- **Table files**: `server_results.txt`, `client_results.txt`
- **Summary files**: `server_summary.txt`, `client_summary.txt`
- **Statistics**: Displayed to stdout

## Performance

- **Single file processing**: Optimized streaming with configurable workers
- **Multiple file processing**: Parallel processing with process pools
- **Large-scale support**: Batch processing for up to 10,000 pcap files
- **Frame number management**: Automatic offset to prevent duplicates
- **Memory efficient**: Configurable batch sizes and buffer management
- **Real-time progress**: Detailed progress monitoring with statistics
- **Default settings**: 8 workers per file, CPU count processes for multiple files

## Parallel Processing

### Single File Processing
- Uses optimized streaming with configurable workers
- Maintains backward compatibility with existing usage
- Real-time progress monitoring

### Multiple File Processing
- **Automatic detection**: Processes single files or directories
- **Parallel execution**: Uses process pools for maximum efficiency
- **Frame number management**: Prevents duplicates across files
- **Batch processing**: Handles large numbers of files efficiently
- **Progress tracking**: Detailed progress with file-by-file status

### Frame Number Offset System
- Each pcap file gets a unique offset (1,000,000 per file)
- Prevents frame number conflicts when aggregating results
- Maintains chronological order within each file
- Enables accurate statistics across multiple files

## Requirements

- pyshark
- Python 3.7+

## Installation

```bash
pip install pyshark
```

## Advanced Usage

### Large-Scale Processing
```bash
# Process thousands of pcap files
python tls_pqc_detector.py massive_pcap_collection/ --processes 16 --workers 4

# Memory-optimized processing
python tls_pqc_detector.py large_directory/ --chunk-size 50 --buffer-size 10000
```