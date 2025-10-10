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
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import Queue
import time
import re
import contextlib
import io
from config import (
    PQC_NAMED_GROUPS, CLASSICAL_NAMED_GROUPS, PQC_SIGNATURE_ALGORITHMS,
    CIPHER_SUITES, TLS_VERSION_PATTERNS, DEFAULT_WORKERS, 
    DEFAULT_CHUNK_SIZE, DEFAULT_BUFFER_SIZE, DEFAULT_MODE
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

        # Extract supported groups - try different approaches
        supported_groups = []
        try:
            # Try the singular form first
            if hasattr(tls_layer, 'handshake_extensions_supported_group'):
                field = tls_layer.handshake_extensions_supported_group
                if field:
                    if isinstance(field, list):
                        supported_groups.extend([str(v) for v in field if v])
                    else:
                        supported_groups.append(str(field))
            
            # Try to get individual group fields directly
            for i in range(10):  # Try up to 10 groups
                group_field_name = f"tls.handshake.extensions.supported_groups_group_{i}"
                try:
                    group_value = tls_layer.get_field(group_field_name)
                    if group_value:
                        supported_groups.append(str(group_value))
                except:
                    pass
            
            # Try alternative naming patterns
            for pattern in [
                "tls.handshake.extensions.supported_groups_group",
                "tls.handshake.extensions.supported_groups_list",
                "tls.handshake.extensions.supported_groups_group_list"
            ]:
                try:
                    field = tls_layer.get_field(pattern)
                    if field:
                        if isinstance(field, list):
                            supported_groups.extend([str(v) for v in field if v])
                        else:
                            supported_groups.append(str(field))
                except:
                    pass
            
            # Try to access the container and look for sub-fields
            if hasattr(tls_layer, 'handshake_extensions_supported_groups'):
                field = tls_layer.handshake_extensions_supported_groups
                if field:
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
            
        except:
            pass

        # Extract key share groups - try different approaches
        key_share_groups = []
        try:
            # Try the singular form first
            if hasattr(tls_layer, 'handshake_extensions_key_share_group'):
                field = tls_layer.handshake_extensions_key_share_group
                if field:
                    if isinstance(field, list):
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
                        if isinstance(field, list):
                            key_share_groups.extend([str(v) for v in field if v])
                        else:
                            key_share_groups.append(str(field))
                        break
                except:
                    continue
            
            
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
                if gi_val is not None:
                    supported_group_ints.append(gi_val)

        key_share_group_ints = []
        for g in key_share_groups:
            if g and g != "None":
                gi_val = _hex_to_int(str(g))
                if gi_val is not None:
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

def run_pyshark_client_hello_streaming(pcap: str, max_workers: int = 4, show_progress: bool = True, chunk_size: int = 50, buffer_size: int = 20000) -> List[ClientHelloInfo]:
    """Optimized streaming processing for TLS ClientHello detection."""
    import pyshark
    from queue import Queue
    import threading
    import time
    import re
    
    results = []
    packet_queue = Queue(maxsize=buffer_size * 2)
    results_lock = threading.Lock()
    processed_count = 0
    total_packets = 0
    start_time = time.time()
    
    # Pre-compile regex patterns for faster processing
    tls_version_patterns = {k: re.compile(v) for k, v in TLS_VERSION_PATTERNS.items()}
    
    def packet_reader():
        nonlocal total_packets
        cap = pyshark.FileCapture(
            pcap, 
            display_filter="tls.handshake.type == 1",  # ClientHello
            keep_packets=False,
            use_json=False,
            include_raw=False,
            override_prefs={
                'tls.desegment_ssl_records': 'FALSE',
                'tls.desegment_ssl_application_data': 'FALSE',
                'tls.keylog_file': '',
                'tls.debug_file': ''
            }
        )
        try:
            for pkt in cap:
                packet_queue.put(pkt)
                total_packets += 1
                
                if show_progress and total_packets % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = total_packets / elapsed if elapsed > 0 else 0
                    print(f"Read: {total_packets} packets (Speed: {rate:.1f} pkt/s)", file=sys.stderr)
        except Exception as e:
            print(f"Packet reading error: {e}", file=sys.stderr)
        finally:
            try:
                cap.close()
            except:
                pass
            packet_queue.put(None)  # Signal end of packets
    
    def packet_processor():
        nonlocal processed_count
        effective_workers = min(max_workers * 2, 16)
        
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = []
            batch_count = 0
            
            while True:
                batch = []
                
                for _ in range(chunk_size):
                    try:
                        pkt = packet_queue.get(timeout=1.0)
                        if pkt is None:
                            break
                        batch.append(pkt)
                    except:
                        break
                
                if not batch:
                    break
                
                batch_count += 1
                
                batch_futures = [executor.submit(process_client_hello_optimized, pkt, tls_version_patterns) for pkt in batch]
                futures.extend(batch_futures)
                
                # Process futures without timeout to avoid blocking
                for future in batch_futures:
                    try:
                        result = future.result(timeout=0.1)
                        if result is not None:
                            with results_lock:
                                results.append(result)
                    except Exception as e:
                        pass
                    
                    processed_count += 1
                    if show_progress and processed_count % 1000 == 0:
                        elapsed = time.time() - start_time
                        rate = processed_count / elapsed if elapsed > 0 else 0
                        print(f"Processed: {processed_count} packets (Speed: {rate:.1f} pkt/s)", file=sys.stderr)
            
            for future in futures:
                try:
                    result = future.result(timeout=0.1)
                    if result is not None:
                        with results_lock:
                            results.append(result)
                except:
                    pass
    
    if show_progress:
        print(f"Streaming ClientHello packets... (Chunk size: {chunk_size}, Workers: {max_workers})", file=sys.stderr)
    
    processor_thread = threading.Thread(target=packet_processor)
    processor_thread.start()
    
    reader_thread = threading.Thread(target=packet_reader)
    reader_thread.start()
    
    reader_thread.join()
    processor_thread.join()
    
    if show_progress:
        elapsed = time.time() - start_time
        rate = total_packets / elapsed if elapsed > 0 else 0
        print(f"Analysis complete: {len(results)} ClientHello packets detected (Total time: {elapsed:.1f}s, Average speed: {rate:.1f} pkt/s)", file=sys.stderr)
    
    return results

def run_pyshark_streaming(pcap: str, max_workers: int = 4, show_progress: bool = True, chunk_size: int = 50, buffer_size: int = 20000) -> List[ServerHelloInfo]:
    """Optimized streaming processing for TLS PQC detection."""
    import pyshark
    from queue import Queue
    import threading
    import time
    import re
    
    results = []
    packet_queue = Queue(maxsize=buffer_size * 2)
    results_lock = threading.Lock()
    processed_count = 0
    total_packets = 0
    start_time = time.time()
    
    # Pre-compile regex patterns for faster processing
    tls_version_patterns = {k: re.compile(v) for k, v in TLS_VERSION_PATTERNS.items()}
    
    def packet_reader():
        nonlocal total_packets
        cap = pyshark.FileCapture(
            pcap, 
            display_filter="tls.handshake.type == 2", 
            keep_packets=False,
            use_json=False,
            include_raw=False,
            override_prefs={
                'tls.desegment_ssl_records': 'FALSE',
                'tls.desegment_ssl_application_data': 'FALSE',
                'tls.keylog_file': '',
                'tls.debug_file': ''
            }
        )
        try:
            for pkt in cap:
                packet_queue.put(pkt)
                total_packets += 1
                
                
                if show_progress and total_packets % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = total_packets / elapsed if elapsed > 0 else 0
                    print(f"Read: {total_packets} packets (Speed: {rate:.1f} pkt/s)", file=sys.stderr)
        except Exception as e:
            print(f"Packet reading error: {e}", file=sys.stderr)
        finally:
            try:
                cap.close()
            except:
                pass
            packet_queue.put(None)  # Signal end of packets
    
    def packet_processor():
        nonlocal processed_count
        effective_workers = min(max_workers * 2, 16)
        
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = []
            batch_count = 0
            
            while True:
                batch = []
                
                for _ in range(chunk_size):
                    try:
                        pkt = packet_queue.get(timeout=1.0)
                        if pkt is None:
                            break
                        batch.append(pkt)
                    except:
                        break
                
                if not batch:
                    break
                
                batch_count += 1
                
                batch_futures = [executor.submit(process_packet_optimized, pkt, tls_version_patterns) for pkt in batch]
                futures.extend(batch_futures)
                
                # Process futures without timeout to avoid blocking
                for future in batch_futures:
                    try:
                        result = future.result(timeout=0.1)
                        if result is not None:
                            with results_lock:
                                results.append(result)
                    except Exception as e:
                        pass
                    
                    processed_count += 1
                    if show_progress and processed_count % 1000 == 0:
                        elapsed = time.time() - start_time
                        rate = processed_count / elapsed if elapsed > 0 else 0
                        print(f"Processed: {processed_count} packets (Speed: {rate:.1f} pkt/s)", file=sys.stderr)
            
            for future in futures:
                try:
                    result = future.result(timeout=0.1)
                    if result is not None:
                        with results_lock:
                            results.append(result)
                except:
                    pass
    
    if show_progress:
        print(f"Streaming packets... (Chunk size: {chunk_size}, Workers: {max_workers})", file=sys.stderr)
    
    processor_thread = threading.Thread(target=packet_processor)
    processor_thread.start()
    
    reader_thread = threading.Thread(target=packet_reader)
    reader_thread.start()
    
    reader_thread.join()
    processor_thread.join()
    
    if show_progress:
        elapsed = time.time() - start_time
        rate = total_packets / elapsed if elapsed > 0 else 0
        print(f"Analysis complete: {len(results)} ServerHello packets detected (Total time: {elapsed:.1f}s, Average speed: {rate:.1f} pkt/s)", file=sys.stderr)
    
    return results

def run_pyshark(pcap: str, max_workers: int = 4, show_progress: bool = True, chunk_size: int = 50, buffer_size: int = 20000) -> List[ServerHelloInfo]:
    """Main function using optimized streaming processing."""
    return run_pyshark_streaming(pcap, max_workers, show_progress, chunk_size, buffer_size)

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
    
    # CipherSuite statistics
    cipher_suites = {}
    cipher_names = {}
    for r in results:
        if r.cipher_suite:
            cipher_suites[r.cipher_suite] = cipher_suites.get(r.cipher_suite, 0) + 1
        if r.cipher_suite_name:
            cipher_names[r.cipher_suite_name] = cipher_names.get(r.cipher_suite_name, 0) + 1
    
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
    
    print(f"\nCipherSuite statistics:")
    print(f"  Total unique CipherSuites: {len(cipher_suites)}")
    print(f"  Total unique CipherNames: {len(cipher_names)}")
    
    if cipher_suites:
        print(f"\nCipherSuite usage frequency (top 10):")
        sorted_ciphers = sorted(cipher_suites.items(), key=lambda x: x[1], reverse=True)
        for cipher, count in sorted_ciphers[:10]:
            percentage = (count / total_packets) * 100
            print(f"  {cipher}: {count} ({percentage:.1f}%)")
    
    if cipher_names:
        print(f"\nCipherName usage frequency (top 10):")
        sorted_names = sorted(cipher_names.items(), key=lambda x: x[1], reverse=True)
        for name, count in sorted_names[:10]:
            percentage = (count / total_packets) * 100
            print(f"  {name}: {count} ({percentage:.1f}%)")
    
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
    ap = argparse.ArgumentParser(description="Detect PQC usage from TLS packets in a pcap/pcapng.")
    ap.add_argument("pcap", help="Input .pcap or .pcapng path")
    ap.add_argument("--mode", choices=['server', 'client', 'both'], default=DEFAULT_MODE, 
                   help="Analysis mode: server (ServerHello), client (ClientHello), or both (default: both)")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of parallel workers (default: 8)")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress output")
    ap.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Chunk size for processing (default: 1000)")
    ap.add_argument("--buffer-size", type=int, default=DEFAULT_BUFFER_SIZE, help="Buffer size for packet queue (default: 20000)")
    args = ap.parse_args()

    show_progress = not args.no_progress
    
    # Create results directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = f"results/{timestamp}"
    os.makedirs(results_dir, exist_ok=True)
    
    print(f"Results will be saved to: {results_dir}/", file=sys.stderr)
    
    # Process ServerHello packets
    if args.mode in ['server', 'both']:
        try:
            server_results = run_pyshark(args.pcap, max_workers=args.workers, show_progress=show_progress, chunk_size=args.chunk_size, buffer_size=args.buffer_size)
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
            client_results = run_pyshark_client_hello_streaming(args.pcap, max_workers=args.workers, show_progress=show_progress, chunk_size=args.chunk_size, buffer_size=args.buffer_size)
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

if __name__ == "__main__":
    main()
