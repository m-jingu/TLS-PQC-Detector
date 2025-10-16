#!/usr/bin/env python3

"""
TLS PQC Detector

TLS PQC (Post-Quantum Cryptography) detection tool for pcap/pcapng files.
Detects TLS ServerHello and ClientHello packets and analyzes PQC algorithm usage.

For detailed documentation, see README.md
"""
import argparse
import json
import sys
import os
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional, Union, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import threading
from queue import Queue
import time
import re
import contextlib
import io
import glob
import multiprocessing as mp
from pathlib import Path
from config import (
    PQC_NAMED_GROUPS, CLASSICAL_NAMED_GROUPS, PQC_SIGNATURE_ALGORITHMS,
    CIPHER_SUITES, TLS_VERSION_PATTERNS, 
    DEFAULT_MODE, GREASE_VALUES
)


@dataclass
class ServerHelloInfo:
    frame: Optional[int]
    src: Optional[str]
    dst: Optional[str]
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    cipher_suite_name: Optional[str]
    named_group_ids: List[str]  # hex strings (e.g., "0xfe31")
    named_group_names: List[str]
    pqc: bool

@dataclass
class ClientHelloInfo:
    frame: Optional[int]
    src: Optional[str]
    dst: Optional[str]
    tls_version: Optional[str]
    supported_groups: List[str]  # hex strings
    supported_group_names: List[str]
    key_share_groups: List[str]  # hex strings
    key_share_group_names: List[str]
    signature_algorithms: List[str]  # hex strings
    signature_algorithm_names: List[str]
    pqc_supported_groups: bool
    pqc_key_share: bool
    pqc_signature: bool
    pqc_any: bool  # Any PQC algorithm detected

@dataclass
class PcapProcessingResult:
    """Processing result for a single pcap file"""
    pcap_file: str
    server_results: List[ServerHelloInfo]
    client_results: List[ClientHelloInfo]
    processing_time: float
    error: Optional[str] = None

class ParallelPcapProcessor:
    """Parallel processing class for multiple pcap files"""
    
    def __init__(self, max_workers: int = 4, max_processes: int = None, 
                 chunk_size: int = 50, buffer_size: int = 20000, 
                 show_progress: bool = True):
        self.max_workers = max_workers
        self.max_processes = max_processes or min(mp.cpu_count(), 8)
        self.chunk_size = chunk_size
        self.buffer_size = buffer_size
        self.show_progress = show_progress
        
    def process_single_pcap(self, pcap_file: str, frame_offset: int = 0, 
                          mode: str = 'both') -> PcapProcessingResult:
        """Process a single pcap file and apply frame number offset"""
        start_time = time.time()
        
        try:
            server_results = []
            client_results = []
            
            if mode in ['server', 'both']:
                server_results = run_pyshark_streaming(
                    pcap_file, 
                    show_progress=False  # Hide individual progress
                )
                # Apply frame number offset
                for result in server_results:
                    if result.frame is not None:
                        result.frame += frame_offset
            
            if mode in ['client', 'both']:
                client_results = run_pyshark_client_hello_streaming(
                    pcap_file,
                    show_progress=False  # Hide individual progress
                )
                # Apply frame number offset
                for result in client_results:
                    if result.frame is not None:
                        result.frame += frame_offset
            
            processing_time = time.time() - start_time
            
            return PcapProcessingResult(
                pcap_file=pcap_file,
                server_results=server_results,
                client_results=client_results,
                processing_time=processing_time
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            return PcapProcessingResult(
                pcap_file=pcap_file,
                server_results=[],
                client_results=[],
                processing_time=processing_time,
                error=str(e)
            )
    
    def process_multiple_pcaps(self, pcap_files: List[str], mode: str = 'both') -> List[PcapProcessingResult]:
        """Process multiple pcap files in parallel"""
        if not pcap_files:
            return []
        
        if self.show_progress:
            print(f"Processing {len(pcap_files)} pcap files with {self.max_processes} processes...", file=sys.stderr)
            print(f"Files to process:", file=sys.stderr)
            for i, pcap_file in enumerate(pcap_files, 1):
                print(f"  {i}. {os.path.basename(pcap_file)}", file=sys.stderr)
        
        # Calculate frame number offsets (each pcap file starts from 1)
        frame_offsets = {}
        current_offset = 0
        
        for pcap_file in pcap_files:
            frame_offsets[pcap_file] = current_offset
            # Set large offset value (actual frame count is unknown)
            current_offset += 1000000  # Assign 1 million offset to each pcap file
        
        
        results = []
        start_time = time.time()
        
        # Use process pool for parallel processing
        with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
            # Schedule processing for each pcap file
            future_to_pcap = {}
            for pcap_file in pcap_files:
                frame_offset = frame_offsets[pcap_file]
                future = executor.submit(self._process_single_pcap_wrapper, 
                                       pcap_file, frame_offset, mode)
                future_to_pcap[future] = pcap_file
            
            # Collect results
            completed = 0
            for future in as_completed(future_to_pcap):
                pcap_file = future_to_pcap[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if self.show_progress:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        progress_percent = (completed / len(pcap_files)) * 100
                        print(f"[{progress_percent:5.1f}%] Completed: {completed}/{len(pcap_files)} files "
                              f"({rate:.1f} files/s) - {os.path.basename(pcap_file)}", 
                              file=sys.stderr)
                        
                except Exception as e:
                    error_result = PcapProcessingResult(
                        pcap_file=pcap_file,
                        server_results=[],
                        client_results=[],
                        processing_time=0,
                        error=str(e)
                    )
                    results.append(error_result)
                    completed += 1
                    
                    if self.show_progress:
                        print(f"[ERROR] Failed to process {os.path.basename(pcap_file)}: {str(e)}", 
                              file=sys.stderr)
        
        if self.show_progress:
            total_time = time.time() - start_time
            successful_files = len([r for r in results if not r.error])
            failed_files = len([r for r in results if r.error])
            print(f"Processing completed: {successful_files} successful, {failed_files} failed in {total_time:.1f}s", file=sys.stderr)
        
        return results
    
    @staticmethod
    def _process_single_pcap_wrapper(pcap_file: str, frame_offset: int, mode: str) -> PcapProcessingResult:
        """Wrapper function for inter-process communication"""
        processor = ParallelPcapProcessor()
        return processor.process_single_pcap(pcap_file, frame_offset, mode)
    
    def aggregate_results(self, results: List[PcapProcessingResult]) -> Tuple[List[ServerHelloInfo], List[ClientHelloInfo]]:
        """Aggregate multiple processing results"""
        all_server_results = []
        all_client_results = []
        
        for result in results:
            if result.error:
                if self.show_progress:
                    print(f"Error processing {result.pcap_file}: {result.error}", file=sys.stderr)
                continue
                
            all_server_results.extend(result.server_results)
            all_client_results.extend(result.client_results)
        
        return all_server_results, all_client_results

def find_pcap_files(input_path: str) -> List[str]:
    """Search for pcap files from input path"""
    pcap_files = []
    
    if os.path.isfile(input_path):
        # Single file
        if input_path.lower().endswith(('.pcap', '.pcapng')):
            pcap_files.append(input_path)
    elif os.path.isdir(input_path):
        # Search for pcap files in directory
        patterns = ['*.pcap', '*.pcapng', '**/*.pcap', '**/*.pcapng']
        for pattern in patterns:
            pcap_files.extend(glob.glob(os.path.join(input_path, pattern), recursive=True))
        pcap_files = sorted(list(set(pcap_files)))  # Remove duplicates and sort
    else:
        # Wildcard pattern
        pcap_files = glob.glob(input_path)
        pcap_files = [f for f in pcap_files if f.lower().endswith(('.pcap', '.pcapng'))]
        pcap_files = list(set(pcap_files))  # Remove duplicates
    
    return pcap_files

def process_pcap_files_batch(pcap_files: List[str], max_processes: int = None, 
                           max_workers: int = 4, mode: str = 'both',
                           chunk_size: int = 50, buffer_size: int = 20000,
                           show_progress: bool = True) -> Tuple[List[ServerHelloInfo], List[ClientHelloInfo]]:
    """Batch process multiple pcap files (large scale support)"""
    if not pcap_files:
        return [], []
    
    if show_progress:
        print(f"Found {len(pcap_files)} pcap files to process", file=sys.stderr)
    
    # Adjust batch size for large number of files
    batch_size = min(100, len(pcap_files))  # Number of files to process at once
    all_server_results = []
    all_client_results = []
    
    processor = ParallelPcapProcessor(
        max_workers=max_workers,
        max_processes=max_processes,
        chunk_size=chunk_size,
        buffer_size=buffer_size,
        show_progress=show_progress
    )
    
    # Batch processing
    for i in range(0, len(pcap_files), batch_size):
        batch_files = pcap_files[i:i + batch_size]
        
        if show_progress:
            batch_num = i//batch_size + 1
            total_batches = (len(pcap_files) + batch_size - 1)//batch_size
            print(f"Processing batch {batch_num}/{total_batches} ({len(batch_files)} files)", file=sys.stderr)
        
        # Process files in batch in parallel
        batch_results = processor.process_multiple_pcaps(batch_files, mode)
        
        # Aggregate results
        batch_server_results, batch_client_results = processor.aggregate_results(batch_results)
        all_server_results.extend(batch_server_results)
        all_client_results.extend(batch_client_results)
        
        if show_progress:
            print(f"Batch {batch_num}/{total_batches} completed: {len(batch_server_results)} ServerHello, "
                  f"{len(batch_client_results)} ClientHello packets", file=sys.stderr)
    
    return all_server_results, all_client_results

def _hex_to_int(s: str) -> Optional[int]:
    try:
        s = s.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        # tshark sometimes gives raw decimal or hex without "0x"
        # try hex first if it looks like hex
        if all(c in "0123456789abcdefABCDEF" for c in s):
            # treat as hex when includes a-f
            if any(c in "abcdefABCDEF" for c in s):
                return int(s, 16)
        # otherwise decimal
        return int(s)
    except Exception:
        return None

def _classify_groups(groups: List[int]) -> (List[str], List[str], bool):
    ids_hex = []
    names = []
    pqc = False
    for g in groups:
        if g is None:
            continue
        ids_hex.append(f"0x{g:04x}")
        if g in PQC_NAMED_GROUPS:
            names.append(PQC_NAMED_GROUPS[g])
            pqc = True
        elif g in CLASSICAL_NAMED_GROUPS:
            names.append(CLASSICAL_NAMED_GROUPS[g])
        else:
            names.append("unknown")
    return ids_hex, names, pqc

def _get_cipher_suite_name(cipher_suite: str) -> Optional[str]:
    """Convert cipher suite hex value to name."""
    if not cipher_suite:
        return None
    try:
        # Remove 0x prefix if present
        hex_str = cipher_suite.replace("0x", "").replace("0X", "")
        if not hex_str:
            return None
        cipher_id = int(hex_str, 16)
        return CIPHER_SUITES.get(cipher_id, None)
    except (ValueError, TypeError):
        return None


def process_client_hello_optimized(pkt, tls_version_patterns) -> Optional[ClientHelloInfo]:
    """Process a ClientHello packet and return ClientHelloInfo or None."""
    try:
        frame_no = None
        try:
            frame_no = int(pkt.frame_info.number)
        except:
            pass
        
        # Extract IP addresses
        ip_src = ip_dst = None
        if hasattr(pkt, 'ip'):
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            ip_src = pkt.ipv6.src
            ip_dst = pkt.ipv6.dst

        # Get TLS layer
        tls_layer = getattr(pkt, "tls", None)
        if not tls_layer:
            return None
        
        # Check if this is a ClientHello packet
        handshake_type = getattr(tls_layer, 'handshake_type', None)
        if handshake_type != '1':
            return None
        
        

        # Detect TLS version
        tls_version = "unknown"
        
        # First try supported_version extension (TLS 1.3)
        supported_ver = None
        try:
            supported_ver = tls_layer.handshake_extensions_supported_version
        except:
            try:
                supported_ver = tls_layer.get_field("tls.handshake.extensions.supported_version")
            except:
                pass
            
        if supported_ver:
            # Handle LayerFieldsContainer (pyshark specific)
            if hasattr(supported_ver, 'all_fields'):
                versions = []
                for field in supported_ver.all_fields:
                    if hasattr(field, 'show'):
                        versions.append(field.show)
                    elif hasattr(field, 'value'):
                        versions.append(field.value)
                    else:
                        versions.append(str(field))
                
                for ver_str in versions:
                    # Skip GREASE values
                    ver_int = _hex_to_int(ver_str)
                    if ver_int is not None and ver_int in GREASE_VALUES:
                        continue
                    for version, pattern in tls_version_patterns.items():
                        if pattern.search(ver_str):
                            tls_version = version
                            break
                    if tls_version != "unknown":
                        break
            # Handle both single values and lists
            elif isinstance(supported_ver, list):
                for ver in supported_ver:
                    ver_str = str(ver)
                    # Skip GREASE values
                    ver_int = _hex_to_int(ver_str)
                    if ver_int is not None and ver_int in GREASE_VALUES:
                        continue
                    for version, pattern in tls_version_patterns.items():
                        if pattern.search(ver_str):
                            tls_version = version
                            break
                    if tls_version != "unknown":
                        break
            else:
                supported_ver_str = str(supported_ver)
                # Skip GREASE values for single values too
                ver_int = _hex_to_int(supported_ver_str)
                if ver_int is None or ver_int not in GREASE_VALUES:
                    for version, pattern in tls_version_patterns.items():
                        if pattern.search(supported_ver_str):
                            tls_version = version
                            break
        
        # If still unknown, try record version (TLS 1.2 and below)
        if tls_version == "unknown":
            record_ver = None
            try:
                record_ver = tls_layer.record_version
            except:
                try:
                    record_ver = tls_layer.get_field("tls.record.version")
                except:
                    pass
                
            if record_ver:
                record_ver_str = str(record_ver)
                for version, pattern in tls_version_patterns.items():
                    if pattern.search(record_ver_str):
                        tls_version = version
                        break

        # Extract supported groups - comprehensive approach
        supported_groups = []
        try:
            # Try multiple field names for supported groups
            supported_group_fields = [
                'handshake_extensions_supported_group',
                'handshake_extensions_supported_groups',
                'handshake_extensions_supported_groups_group',
                'handshake_extensions_supported_groups_list'
            ]
            
            for field_name in supported_group_fields:
                if hasattr(tls_layer, field_name):
                    field = getattr(tls_layer, field_name)
                    if field:
                        # Handle LayerFieldsContainer (pyshark specific)
                        if hasattr(field, 'all_fields'):
                            for subfield in field.all_fields:
                                if hasattr(subfield, 'show'):
                                    supported_groups.append(subfield.show)
                                elif hasattr(subfield, 'value'):
                                    supported_groups.append(subfield.value)
                                else:
                                    supported_groups.append(str(subfield))
                        elif isinstance(field, list):
                            supported_groups.extend([str(v) for v in field if v])
                        else:
                            supported_groups.append(str(field))
                        break
            
            # Try alternative field names
            for field_name in [
                "tls.handshake.extensions.supported_groups_group",
                "tls.handshake.extensions.supported_groups_list",
                "tls.handshake.extensions.supported_groups_group_list"
            ]:
                try:
                    field = tls_layer.get_field(field_name)
                    if field:
                        # Handle LayerFieldsContainer (pyshark specific)
                        if hasattr(field, 'all_fields'):
                            for subfield in field.all_fields:
                                if hasattr(subfield, 'show'):
                                    supported_groups.append(subfield.show)
                                elif hasattr(subfield, 'value'):
                                    supported_groups.append(subfield.value)
                                else:
                                    supported_groups.append(str(subfield))
                        elif isinstance(field, list):
                            supported_groups.extend([str(v) for v in field if v])
                        else:
                            supported_groups.append(str(field))
                        break
                except:
                    continue
            
            # Try to get individual group fields directly
            for i in range(10):  # Try up to 10 groups
                group_field_name = f"tls.handshake.extensions.supported_groups_group_{i}"
                try:
                    group_value = tls_layer.get_field(group_field_name)
                    if group_value:
                        supported_groups.append(str(group_value))
                except:
                    pass
            
            # Try to access the container and look for sub-fields
            if hasattr(tls_layer, 'handshake_extensions_supported_groups'):
                field = tls_layer.handshake_extensions_supported_groups
                if field:
                    # Handle LayerFieldsContainer (pyshark specific)
                    if hasattr(field, 'all_fields'):
                        for subfield in field.all_fields:
                            if hasattr(subfield, 'show'):
                                supported_groups.append(subfield.show)
                            elif hasattr(subfield, 'value'):
                                supported_groups.append(subfield.value)
                            else:
                                supported_groups.append(str(subfield))
                    # Try to access fields attribute
                    try:
                        if hasattr(field, 'fields'):
                            fields = field.fields
                            if fields:
                                for f in fields:
                                    if hasattr(f, 'name') and 'group' in f.name.lower():
                                        # Try to get the actual value
                                        try:
                                            if hasattr(f, 'int_value') and f.int_value is not None:
                                                supported_groups.append(str(f.int_value))
                                            elif hasattr(f, 'hex_value') and f.hex_value:
                                                supported_groups.append(str(f.hex_value))
                                            elif hasattr(f, 'value') and f.value:
                                                supported_groups.append(str(f.value))
                                        except:
                                            pass
                    except:
                        pass
            
            # Remove duplicates and empty values while preserving order
            seen = set()
            supported_groups = [x for x in supported_groups if x and x.strip() and not (x in seen or seen.add(x))]
            
        except:
            pass

        # Extract key share groups - try different approaches
        key_share_groups = []
        try:
            # Try the singular form first
            if hasattr(tls_layer, 'handshake_extensions_key_share_group'):
                field = tls_layer.handshake_extensions_key_share_group
                if field:
                    # Handle LayerFieldsContainer (pyshark specific)
                    if hasattr(field, 'all_fields'):
                        for subfield in field.all_fields:
                            if hasattr(subfield, 'show'):
                                key_share_groups.append(subfield.show)
                            elif hasattr(subfield, 'value'):
                                key_share_groups.append(subfield.value)
                            else:
                                key_share_groups.append(str(subfield))
                    elif isinstance(field, list):
                        key_share_groups.extend([str(v) for v in field if v])
                    else:
                        key_share_groups.append(str(field))
            
            # Try alternative field names based on Wireshark structure
            for field_name in [
                "tls.handshake.extensions.key_share_group",
                "tls.handshake.extensions.key_share",
                "tls.handshake.extensions.key_share_group_list",
                "tls.handshake.extensions.key_share_entry",
                "tls.handshake.extensions.key_share_entry_group"
            ]:
                try:
                    field = tls_layer.get_field(field_name)
                    if field:
                        # Handle LayerFieldsContainer (pyshark specific)
                        if hasattr(field, 'all_fields'):
                            for subfield in field.all_fields:
                                if hasattr(subfield, 'show'):
                                    key_share_groups.append(subfield.show)
                                elif hasattr(subfield, 'value'):
                                    key_share_groups.append(subfield.value)
                                else:
                                    key_share_groups.append(str(subfield))
                        elif isinstance(field, list):
                            key_share_groups.extend([str(v) for v in field if v])
                        else:
                            key_share_groups.append(str(field))
                        break
                except:
                    continue
            
            # Remove duplicates while preserving order
            seen = set()
            key_share_groups = [x for x in key_share_groups if not (x in seen or seen.add(x))]
            
        except:
            pass

        # Extract signature algorithms - use the correct field names
        signature_algorithms = []
        try:
            # Try the correct field names based on debug output
            for field_name in [
                'handshake_sig_hash_alg',
                'handshake_sig_hash_algs',
                'handshake_sig_hash_hash',
                'handshake_sig_hash_sig'
            ]:
                if hasattr(tls_layer, field_name):
                    field = getattr(tls_layer, field_name)
                    if field:
                        if isinstance(field, list):
                            signature_algorithms.extend([str(v) for v in field if v])
                        else:
                            signature_algorithms.append(str(field))
            
            # Try alternative field names
            for field_name in [
                "tls.handshake.extensions.signature_algorithms",
                "tls.handshake.extensions.signature_algorithms_algorithm",
                "tls.handshake.extensions.signature_algorithms_list"
            ]:
                try:
                    field = tls_layer.get_field(field_name)
                    if field:
                        if isinstance(field, list):
                            signature_algorithms.extend([str(v) for v in field if v])
                        else:
                            signature_algorithms.append(str(field))
                        break
                except:
                    continue
            
        except:
            pass

        # Convert to integers and classify
        supported_group_ints = []
        for g in supported_groups:
            if g and g != "None":
                gi_val = _hex_to_int(str(g))
                if gi_val is not None and gi_val not in GREASE_VALUES:
                    supported_group_ints.append(gi_val)

        key_share_group_ints = []
        for g in key_share_groups:
            if g and g != "None":
                gi_val = _hex_to_int(str(g))
                if gi_val is not None and gi_val not in GREASE_VALUES:
                    key_share_group_ints.append(gi_val)

        signature_algorithm_ints = []
        for s in signature_algorithms:
            if s and s != "None":
                si_val = _hex_to_int(str(s))
                if si_val is not None:
                    signature_algorithm_ints.append(si_val)

        # Classify groups and algorithms
        supported_ids_hex, supported_names, supported_pqc = _classify_groups(supported_group_ints)
        key_share_ids_hex, key_share_names, key_share_pqc = _classify_groups(key_share_group_ints)
        
        # Classify signature algorithms
        signature_ids_hex = []
        signature_names = []
        signature_pqc = False
        for s in signature_algorithm_ints:
            signature_ids_hex.append(f"0x{s:04x}")
            if s in PQC_SIGNATURE_ALGORITHMS:
                signature_names.append(PQC_SIGNATURE_ALGORITHMS[s])
                signature_pqc = True
            else:
                signature_names.append("classical")

        # Determine PQC presence
        pqc_any = supported_pqc or key_share_pqc or signature_pqc


        return ClientHelloInfo(
            frame=frame_no,
            src=ip_src,
            dst=ip_dst,
            tls_version=tls_version,
            supported_groups=supported_ids_hex,
            supported_group_names=supported_names,
            key_share_groups=key_share_ids_hex,
            key_share_group_names=key_share_names,
            signature_algorithms=signature_ids_hex,
            signature_algorithm_names=signature_names,
            pqc_supported_groups=supported_pqc,
            pqc_key_share=key_share_pqc,
            pqc_signature=signature_pqc,
            pqc_any=pqc_any,
        )
    except Exception as e:
        return None

def process_packet_optimized(pkt, tls_version_patterns) -> Optional[ServerHelloInfo]:
    """Process a single packet and return ServerHelloInfo or None."""
    try:
        frame_no = None
        try:
            frame_no = int(pkt.frame_info.number)
        except:
            pass
        
        # Extract IP addresses
        ip_src = ip_dst = None
        if hasattr(pkt, 'ip'):
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            ip_src = pkt.ipv6.src
            ip_dst = pkt.ipv6.dst

        # Get TLS layer
        tls_layer = getattr(pkt, "tls", None)
        if not tls_layer:
            return None
        
        # Check if this is a ServerHello packet
        handshake_type = getattr(tls_layer, 'handshake_type', None)
        if handshake_type != '2':
            return None
            
        # Extract cipher suite
        cipher_suite = None
        try:
            cipher_suite = tls_layer.handshake_ciphersuite
        except:
            try:
                cipher_suite = tls_layer.get_field("tls.handshake.ciphersuite")
            except:
                pass
        
        cipher_suite_name = _get_cipher_suite_name(cipher_suite) if cipher_suite else None

        # Detect TLS version
        tls_version = "unknown"
        
        supported_ver = None
        try:
            supported_ver = tls_layer.handshake_extensions_supported_version
        except:
            try:
                supported_ver = tls_layer.get_field("tls.handshake.extensions.supported_version")
            except:
                pass
            
        if supported_ver:
            supported_ver_str = str(supported_ver)
            for version, pattern in tls_version_patterns.items():
                if pattern.search(supported_ver_str):
                    tls_version = version
                    break
        
        if tls_version == "unknown":
            record_ver = None
            try:
                record_ver = tls_layer.record_version
            except:
                try:
                    record_ver = tls_layer.get_field("tls.record.version")
                except:
                    pass
                
            if record_ver:
                record_ver_str = str(record_ver)
                for version, pattern in tls_version_patterns.items():
                    if pattern.search(record_ver_str):
                        tls_version = version
                        break

        # Extract key_share groups
        groups = []
        try:
            key_share_field = tls_layer.get_field("tls.handshake.extensions.key_share_group")
            if key_share_field:
                if isinstance(key_share_field, list):
                    groups.extend([str(v) for v in key_share_field if v])
                else:
                    groups.append(str(key_share_field))
        except:
            pass
        
        # Convert groups to integers
        group_ints = []
        for g in groups:
            if g and g != "None":
                gi_val = _hex_to_int(str(g))
                if gi_val is not None:
                    group_ints.append(gi_val)
        
        ids_hex, names, pqc = _classify_groups(group_ints)
        
        return ServerHelloInfo(
            frame=frame_no,
            src=ip_src,
            dst=ip_dst,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            cipher_suite_name=cipher_suite_name,
            named_group_ids=ids_hex,
            named_group_names=names,
            pqc=pqc if tls_version == "TLS 1.3" else False,
        )
    except Exception as e:
        return None

def run_pyshark_client_hello_streaming(pcap: str, show_progress: bool = True) -> List[ClientHelloInfo]:
    """Single-threaded processing for TLS ClientHello detection."""
    import pyshark
    import time
    import re
    
    results = []
    start_time = time.time()
    
    # Pre-compile regex patterns for faster processing
    tls_version_patterns = {k: re.compile(v) for k, v in TLS_VERSION_PATTERNS.items()}
    
    if show_progress:
        print(f"Processing ClientHello packets from {pcap}...", file=sys.stderr)
    
    # Use the exact same approach as direct testing
    cap = pyshark.FileCapture(pcap, display_filter='tls')
    
    try:
        for pkt in cap:
            # Process all TLS packets - let process_client_hello_optimized handle the filtering
            result = process_client_hello_optimized(pkt, tls_version_patterns)
            if result is not None:
                results.append(result)
    except Exception as e:
        print(f"Packet processing error: {e}", file=sys.stderr)
    finally:
        try:
            cap.close()
        except:
            pass
    
    if show_progress:
        elapsed = time.time() - start_time
        print(f"Analysis complete: {len(results)} ClientHello packets detected (Total time: {elapsed:.1f}s)", file=sys.stderr)
    
    return results

def run_pyshark_streaming(pcap: str, show_progress: bool = True) -> List[ServerHelloInfo]:
    """Single-threaded processing for TLS PQC detection."""
    import pyshark
    import time
    import re
    
    results = []
    start_time = time.time()
    
    # Pre-compile regex patterns for faster processing
    tls_version_patterns = {k: re.compile(v) for k, v in TLS_VERSION_PATTERNS.items()}
    
    if show_progress:
        print(f"Processing ServerHello packets from {pcap}...", file=sys.stderr)
    
    # Use the exact same approach as direct testing
    cap = pyshark.FileCapture(pcap, display_filter='tls')
    
    try:
        for pkt in cap:
            # Process all TLS packets - let process_packet_optimized handle the filtering
            result = process_packet_optimized(pkt, tls_version_patterns)
            if result is not None:
                results.append(result)
    except Exception as e:
        print(f"Packet processing error: {e}", file=sys.stderr)
    finally:
        try:
            cap.close()
        except:
            pass
    
    if show_progress:
        elapsed = time.time() - start_time
        print(f"Analysis complete: {len(results)} ServerHello packets detected (Total time: {elapsed:.1f}s)", file=sys.stderr)
    
    return results

def run_pyshark(pcap: str, show_progress: bool = True) -> List[ServerHelloInfo]:
    """Main function using single-threaded processing."""
    return run_pyshark_streaming(pcap, show_progress)

def print_statistics(results: List[ServerHelloInfo]) -> None:
    """Print statistics about the TLS ServerHello packets."""
    if not results:
        return
    
    total_packets = len(results)
    pqc_packets = sum(1 for r in results if r.pqc)
    pqc_rate = (pqc_packets / total_packets) * 100 if total_packets > 0 else 0
    
    # TLS version statistics
    tls_versions = {}
    for r in results:
        version = r.tls_version or "unknown"
        tls_versions[version] = tls_versions.get(version, 0) + 1
    
    # NamedGroup statistics
    all_named_groups = set()
    pqc_named_groups = set()
    classical_named_groups = set()
    
    for r in results:
        for group_name in r.named_group_names:
            if group_name != "unknown":
                all_named_groups.add(group_name)
                if r.pqc:
                    pqc_named_groups.add(group_name)
                else:
                    classical_named_groups.add(group_name)
    
    # CipherName statistics
    cipher_names = {}
    for r in results:
        if r.cipher_suite_name:
            cipher_names[r.cipher_suite_name] = cipher_names.get(r.cipher_suite_name, 0) + 1
    
    # PQC NamedGroups usage frequency
    pqc_named_groups_usage = {}
    for r in results:
        if r.named_group_ids and r.pqc:
            for group_id in r.named_group_ids:
                # Convert hex string to int for lookup
                group_int = int(group_id, 16)
                group_name = PQC_NAMED_GROUPS.get(group_int, CLASSICAL_NAMED_GROUPS.get(group_int, f"unknown_{group_id}"))
                # Check if it's a PQC group
                if group_int in PQC_NAMED_GROUPS:
                    pqc_named_groups_usage[group_name] = pqc_named_groups_usage.get(group_name, 0) + 1
    
    # Print statistics
    print("\n" + "=" * 80)
    print("ServerHello Statistics")
    print("=" * 80)
    
    print(f"Total ServerHello packets: {total_packets}")
    print(f"PQC packets: {pqc_packets}")
    print(f"PQC utilization rate: {pqc_rate:.1f}%")
    
    print(f"\nTLS version distribution:")
    for version, count in sorted(tls_versions.items()):
        percentage = (count / total_packets) * 100
        print(f"  {version}: {count} ({percentage:.1f}%)")
    
    print(f"\nNamedGroup statistics:")
    print(f"  Total unique NamedGroups: {len(all_named_groups)}")
    print(f"  PQC NamedGroups: {len(pqc_named_groups)}")
    print(f"  Classical NamedGroups: {len(classical_named_groups)}")
    
    if pqc_named_groups:
        print(f"\nPQC NamedGroups list:")
        for group in sorted(pqc_named_groups):
            print(f"  - {group}")
    
    if classical_named_groups:
        print(f"\nClassical NamedGroups list:")
        for group in sorted(classical_named_groups):
            print(f"  - {group}")
    
    if pqc_named_groups_usage:
        print(f"\nPQC NamedGroups usage frequency (top 10):")
        sorted_pqc_groups = sorted(pqc_named_groups_usage.items(), key=lambda x: x[1], reverse=True)
        for group, count in sorted_pqc_groups[:10]:
            percentage = (count / total_packets) * 100
            print(f"  {group}: {count} ({percentage:.1f}%)")
    
    if cipher_names:
        print(f"\nCipherName usage frequency (top 10):")
        sorted_cipher_names = sorted(cipher_names.items(), key=lambda x: x[1], reverse=True)
        for cipher_name, count in sorted_cipher_names[:10]:
            percentage = (count / total_packets) * 100
            print(f"  {cipher_name}: {count} ({percentage:.1f}%)")
    
    print("=" * 80)

def print_client_hello_statistics(results: List[ClientHelloInfo]) -> None:
    """Print statistics about the TLS ClientHello packets."""
    if not results:
        return
    
    total_packets = len(results)
    pqc_any_packets = sum(1 for r in results if r.pqc_any)
    pqc_supported_groups_packets = sum(1 for r in results if r.pqc_supported_groups)
    pqc_key_share_packets = sum(1 for r in results if r.pqc_key_share)
    pqc_signature_packets = sum(1 for r in results if r.pqc_signature)
    
    pqc_any_rate = (pqc_any_packets / total_packets) * 100 if total_packets > 0 else 0
    pqc_supported_groups_rate = (pqc_supported_groups_packets / total_packets) * 100 if total_packets > 0 else 0
    pqc_key_share_rate = (pqc_key_share_packets / total_packets) * 100 if total_packets > 0 else 0
    pqc_signature_rate = (pqc_signature_packets / total_packets) * 100 if total_packets > 0 else 0
    
    # TLS version statistics
    tls_versions = {}
    for r in results:
        version = r.tls_version or "unknown"
        tls_versions[version] = tls_versions.get(version, 0) + 1
    
    # Supported groups statistics
    all_supported_groups = set()
    pqc_supported_groups = set()
    classical_supported_groups = set()
    
    for r in results:
        for group_name in r.supported_group_names:
            if group_name != "unknown":
                all_supported_groups.add(group_name)
                if r.pqc_supported_groups:
                    pqc_supported_groups.add(group_name)
                else:
                    classical_supported_groups.add(group_name)
    
    # Key share groups statistics
    all_key_share_groups = set()
    pqc_key_share_groups = set()
    classical_key_share_groups = set()
    
    
    for r in results:
        for group_name in r.key_share_group_names:
            if group_name != "unknown":
                all_key_share_groups.add(group_name)
                if r.pqc_key_share:
                    pqc_key_share_groups.add(group_name)
                else:
                    classical_key_share_groups.add(group_name)
    
    # Signature algorithms statistics
    all_signature_algorithms = set()
    pqc_signature_algorithms = set()
    classical_signature_algorithms = set()
    
    for r in results:
        for sig_name in r.signature_algorithm_names:
            if sig_name != "unknown":
                all_signature_algorithms.add(sig_name)
                if r.pqc_signature:
                    pqc_signature_algorithms.add(sig_name)
                else:
                    classical_signature_algorithms.add(sig_name)
    
    # Print statistics
    print("\n" + "=" * 80)
    print("ClientHello Statistics")
    print("=" * 80)
    
    print(f"Total ClientHello packets: {total_packets}")
    print(f"PQC packets (any): {pqc_any_packets}")
    print(f"PQC utilization rate (any): {pqc_any_rate:.1f}%")
    
    print(f"\nPQC algorithm utilization by type:")
    print(f"  Supported Groups PQC: {pqc_supported_groups_packets} ({pqc_supported_groups_rate:.1f}%)")
    print(f"  Key Share PQC: {pqc_key_share_packets} ({pqc_key_share_rate:.1f}%)")
    print(f"  Signature PQC: {pqc_signature_packets} ({pqc_signature_rate:.1f}%)")
    
    print(f"\nTLS version distribution:")
    for version, count in sorted(tls_versions.items()):
        percentage = (count / total_packets) * 100
        print(f"  {version}: {count} ({percentage:.1f}%)")
    
    print(f"\nSupported Groups statistics:")
    print(f"  Total unique Supported Groups: {len(all_supported_groups)}")
    print(f"  PQC Supported Groups: {len(pqc_supported_groups)}")
    print(f"  Classical Supported Groups: {len(classical_supported_groups)}")
    
    if pqc_supported_groups:
        print(f"\nPQC Supported Groups list:")
        for group in sorted(pqc_supported_groups):
            print(f"  - {group}")
    
    if classical_supported_groups:
        print(f"\nClassical Supported Groups list:")
        for group in sorted(classical_supported_groups):
            print(f"  - {group}")
    
    print(f"\nKey Share Groups statistics:")
    print(f"  Total unique Key Share Groups: {len(all_key_share_groups)}")
    print(f"  PQC Key Share Groups: {len(pqc_key_share_groups)}")
    print(f"  Classical Key Share Groups: {len(classical_key_share_groups)}")
    
    if pqc_key_share_groups:
        print(f"\nPQC Key Share Groups list:")
        for group in sorted(pqc_key_share_groups):
            print(f"  - {group}")
    
    if classical_key_share_groups:
        print(f"\nClassical Key Share Groups list:")
        for group in sorted(classical_key_share_groups):
            print(f"  - {group}")
    
    print(f"\nSignature Algorithms statistics:")
    print(f"  Total unique Signature Algorithms: {len(all_signature_algorithms)}")
    print(f"  PQC Signature Algorithms: {len(pqc_signature_algorithms)}")
    print(f"  Classical Signature Algorithms: {len(classical_signature_algorithms)}")
    
    if pqc_signature_algorithms:
        print(f"\nPQC Signature Algorithms list:")
        for sig in sorted(pqc_signature_algorithms):
            print(f"  - {sig}")
    
    if classical_signature_algorithms:
        print(f"\nClassical Signature Algorithms list:")
        for sig in sorted(classical_signature_algorithms):
            print(f"  - {sig}")
    
    print("=" * 80)

def main():
    ap = argparse.ArgumentParser(description="Detect PQC usage from TLS packets in pcap/pcapng files.")
    ap.add_argument("input", help="Input .pcap/.pcapng file, directory, or wildcard pattern")
    ap.add_argument("--mode", choices=['server', 'client', 'both'], default=DEFAULT_MODE, 
                   help="Analysis mode: server (ServerHello), client (ClientHello), or both (default: both)")
    ap.add_argument("--processes", type=int, default=None, help="Number of parallel processes for multiple files (default: CPU count)")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress output")
    args = ap.parse_args()

    show_progress = not args.no_progress
    
    # Create results directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = f"results/{timestamp}"
    os.makedirs(results_dir, exist_ok=True)
    
    print(f"Results will be saved to: {results_dir}/", file=sys.stderr)
    
    # Find pcap files
    pcap_files = find_pcap_files(args.input)
    
    if not pcap_files:
        print(f"No pcap files found in: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if len(pcap_files) == 1:
        # Single file processing (maintain existing functionality)
        if show_progress:
            print(f"Processing single file: {pcap_files[0]}", file=sys.stderr)
        
        # Process ServerHello packets
        if args.mode in ['server', 'both']:
            try:
                server_results = run_pyshark(pcap_files[0], show_progress=show_progress)
            except ImportError:
                print("pyshark not available. Please install pyshark: pip install pyshark", file=sys.stderr)
                sys.exit(1)

            if not server_results:
                print("No TLS ServerHello packets found or parsing failed.", file=sys.stderr)
                if args.mode == 'server':
                    sys.exit(2)
            else:
                # Output ServerHello statistics to stdout
                print_statistics(server_results)
                
                # Save ServerHello JSON
                server_json_path = f"{results_dir}/server_results.json"
                with open(server_json_path, 'w', encoding='utf-8') as f:
                    json.dump([asdict(r) for r in server_results], f, ensure_ascii=False, indent=2)
                print(f"ServerHello JSON saved to: {server_json_path}", file=sys.stderr)
                
                # Save ServerHello detailed table
                server_table_path = f"{results_dir}/server_results.txt"
                with open(server_table_path, 'w', encoding='utf-8') as f:
                    from shutil import get_terminal_size
                    width = get_terminal_size((120, 20)).columns

                    f.write("=" * width + "\n")
                    f.write("ServerHello Detailed Table\n")
                    f.write("=" * width + "\n")
                    f.write(f"{'Frame':>6}  {'Src':<35}  {'Dst':<35}  {'TLS':<8}  {'PQC':<4}  {'NamedGroup(s)':<20}  {'CipherSuite':<12}  {'CipherName':<30}\n")
                    f.write("-" * width + "\n")
                    for r in server_results:
                        ids = ",".join(r.named_group_ids) if r.named_group_ids else "-"
                        name = "/".join(r.named_group_names) if r.named_group_names else "-"
                        ng = f"{ids} ({name})" if ids != "-" else "-"
                        cipher_hex = str(r.cipher_suite or '-')
                        cipher_name = str(r.cipher_suite_name or '-')
                        f.write(f"{str(r.frame or '-'):>6}  {str(r.src or '-'):<35}  {str(r.dst or '-'):<35}  {str(r.tls_version or '-'):<8}  {str(r.pqc):<4}  {ng:<20}  {cipher_hex:<12}  {cipher_name:<30}\n")
                    f.write("=" * width + "\n")
                print(f"ServerHello table saved to: {server_table_path}", file=sys.stderr)
                
                # Save ServerHello summary
                server_summary_path = f"{results_dir}/server_summary.txt"
                with open(server_summary_path, 'w', encoding='utf-8') as f:
                    # Capture stdout for statistics
                    import io
                    from contextlib import redirect_stdout
                    output = io.StringIO()
                    with redirect_stdout(output):
                        print_statistics(server_results)
                    f.write(output.getvalue())
                print(f"ServerHello summary saved to: {server_summary_path}", file=sys.stderr)

        # Process ClientHello packets
        if args.mode in ['client', 'both']:
            try:
                client_results = run_pyshark_client_hello_streaming(pcap_files[0], show_progress=show_progress)
            except ImportError:
                print("pyshark not available. Please install pyshark: pip install pyshark", file=sys.stderr)
                sys.exit(1)

            if not client_results:
                print("No TLS ClientHello packets found or parsing failed.", file=sys.stderr)
                if args.mode == 'client':
                    sys.exit(2)
            else:
                # Output ClientHello statistics to stdout
                print_client_hello_statistics(client_results)
                
                # Save ClientHello JSON
                client_json_path = f"{results_dir}/client_results.json"
                with open(client_json_path, 'w', encoding='utf-8') as f:
                    json.dump([asdict(r) for r in client_results], f, ensure_ascii=False, indent=2)
                print(f"ClientHello JSON saved to: {client_json_path}", file=sys.stderr)
                
                # Save ClientHello detailed table
                client_table_path = f"{results_dir}/client_results.txt"
                with open(client_table_path, 'w', encoding='utf-8') as f:
                    from shutil import get_terminal_size
                    width = get_terminal_size((120, 20)).columns

                    f.write("=" * width + "\n")
                    f.write("ClientHello Detailed Table\n")
                    f.write("=" * width + "\n")
                    f.write(f"{'Frame':>6}  {'Src':<35}  {'Dst':<35}  {'TLS':<8}  {'PQC':<4}  {'SupportedGroups':<30}  {'KeyShareGroups':<30}  {'SignatureAlgs':<30}\n")
                    f.write("-" * width + "\n")
                    for r in client_results:
                        supported_groups = ",".join(r.supported_group_names) if r.supported_group_names else "-"
                        key_share_groups = ",".join(r.key_share_group_names) if r.key_share_group_names else "-"
                        signature_algs = ",".join(r.signature_algorithm_names) if r.signature_algorithm_names else "-"
                        f.write(f"{str(r.frame or '-'):>6}  {str(r.src or '-'):<35}  {str(r.dst or '-'):<35}  {str(r.tls_version or '-'):<8}  {str(r.pqc_any):<4}  {supported_groups:<30}  {key_share_groups:<30}  {signature_algs:<30}\n")
                    f.write("=" * width + "\n")
                print(f"ClientHello table saved to: {client_table_path}", file=sys.stderr)
                
                # Save ClientHello summary
                client_summary_path = f"{results_dir}/client_summary.txt"
                with open(client_summary_path, 'w', encoding='utf-8') as f:
                    # Capture stdout for statistics
                    import io
                    from contextlib import redirect_stdout
                    output = io.StringIO()
                    with redirect_stdout(output):
                        print_client_hello_statistics(client_results)
                    f.write(output.getvalue())
                print(f"ClientHello summary saved to: {client_summary_path}", file=sys.stderr)
    
    else:
        # Multiple file processing (new parallel processing functionality)
        if show_progress:
            print(f"Processing {len(pcap_files)} pcap files in parallel", file=sys.stderr)
        
        try:
            # Process multiple pcap files in parallel
            server_results, client_results = process_pcap_files_batch(
                pcap_files, 
                max_processes=args.processes,
                max_workers=4,  # Default value
                mode=args.mode,
                chunk_size=1000,  # Default value
                buffer_size=10000,  # Default value
                show_progress=show_progress
            )
            
            # Process ServerHello packets
            if args.mode in ['server', 'both'] and server_results:
                # Output ServerHello statistics to stdout
                print_statistics(server_results)
                
                # Save ServerHello JSON
                server_json_path = f"{results_dir}/server_results.json"
                with open(server_json_path, 'w', encoding='utf-8') as f:
                    json.dump([asdict(r) for r in server_results], f, ensure_ascii=False, indent=2)
                print(f"ServerHello JSON saved to: {server_json_path}", file=sys.stderr)
                
                # Save ServerHello detailed table
                server_table_path = f"{results_dir}/server_results.txt"
                with open(server_table_path, 'w', encoding='utf-8') as f:
                    from shutil import get_terminal_size
                    width = get_terminal_size((120, 20)).columns

                    f.write("=" * width + "\n")
                    f.write("ServerHello Detailed Table (Multiple Files)\n")
                    f.write("=" * width + "\n")
                    f.write(f"{'Frame':>6}  {'Src':<35}  {'Dst':<35}  {'TLS':<8}  {'PQC':<4}  {'NamedGroup(s)':<20}  {'CipherSuite':<12}  {'CipherName':<30}\n")
                    f.write("-" * width + "\n")
                    for r in server_results:
                        ids = ",".join(r.named_group_ids) if r.named_group_ids else "-"
                        name = "/".join(r.named_group_names) if r.named_group_names else "-"
                        ng = f"{ids} ({name})" if ids != "-" else "-"
                        cipher_hex = str(r.cipher_suite or '-')
                        cipher_name = str(r.cipher_suite_name or '-')
                        f.write(f"{str(r.frame or '-'):>6}  {str(r.src or '-'):<35}  {str(r.dst or '-'):<35}  {str(r.tls_version or '-'):<8}  {str(r.pqc):<4}  {ng:<20}  {cipher_hex:<12}  {cipher_name:<30}\n")
                    f.write("=" * width + "\n")
                print(f"ServerHello table saved to: {server_table_path}", file=sys.stderr)
                
                # Save ServerHello summary
                server_summary_path = f"{results_dir}/server_summary.txt"
                with open(server_summary_path, 'w', encoding='utf-8') as f:
                    # Capture stdout for statistics
                    import io
                    from contextlib import redirect_stdout
                    output = io.StringIO()
                    with redirect_stdout(output):
                        print_statistics(server_results)
                    f.write(output.getvalue())
                print(f"ServerHello summary saved to: {server_summary_path}", file=sys.stderr)
            elif args.mode in ['server', 'both']:
                print("No TLS ServerHello packets found in any files.", file=sys.stderr)

            # Process ClientHello packets
            if args.mode in ['client', 'both'] and client_results:
                # Output ClientHello statistics to stdout
                print_client_hello_statistics(client_results)
                
                # Save ClientHello JSON
                client_json_path = f"{results_dir}/client_results.json"
                with open(client_json_path, 'w', encoding='utf-8') as f:
                    json.dump([asdict(r) for r in client_results], f, ensure_ascii=False, indent=2)
                print(f"ClientHello JSON saved to: {client_json_path}", file=sys.stderr)
                
                # Save ClientHello detailed table
                client_table_path = f"{results_dir}/client_results.txt"
                with open(client_table_path, 'w', encoding='utf-8') as f:
                    from shutil import get_terminal_size
                    width = get_terminal_size((120, 20)).columns

                    f.write("=" * width + "\n")
                    f.write("ClientHello Detailed Table (Multiple Files)\n")
                    f.write("=" * width + "\n")
                    f.write(f"{'Frame':>6}  {'Src':<35}  {'Dst':<35}  {'TLS':<8}  {'PQC':<4}  {'SupportedGroups':<30}  {'KeyShareGroups':<30}  {'SignatureAlgs':<30}\n")
                    f.write("-" * width + "\n")
                    for r in client_results:
                        supported_groups = ",".join(r.supported_group_names) if r.supported_group_names else "-"
                        key_share_groups = ",".join(r.key_share_group_names) if r.key_share_group_names else "-"
                        signature_algs = ",".join(r.signature_algorithm_names) if r.signature_algorithm_names else "-"
                        f.write(f"{str(r.frame or '-'):>6}  {str(r.src or '-'):<35}  {str(r.dst or '-'):<35}  {str(r.tls_version or '-'):<8}  {str(r.pqc_any):<4}  {supported_groups:<30}  {key_share_groups:<30}  {signature_algs:<30}\n")
                    f.write("=" * width + "\n")
                print(f"ClientHello table saved to: {client_table_path}", file=sys.stderr)
                
                # Save ClientHello summary
                client_summary_path = f"{results_dir}/client_summary.txt"
                with open(client_summary_path, 'w', encoding='utf-8') as f:
                    # Capture stdout for statistics
                    import io
                    from contextlib import redirect_stdout
                    output = io.StringIO()
                    with redirect_stdout(output):
                        print_client_hello_statistics(client_results)
                    f.write(output.getvalue())
                print(f"ClientHello summary saved to: {client_summary_path}", file=sys.stderr)
            elif args.mode in ['client', 'both']:
                print("No TLS ClientHello packets found in any files.", file=sys.stderr)
                
        except ImportError:
            print("pyshark not available. Please install pyshark: pip install pyshark", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error processing files: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
