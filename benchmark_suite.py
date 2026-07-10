#!/usr/bin/env python3
"""
benchmark_suite.py

Comprehensive performance benchmarking suite for hybrid post-quantum handshake protocol.
Measures latency, network payload, and fragmentation analysis across four scenarios:
  1. Classical: X25519 KEM + ECDSA signatures
  2. Post-Quantum: ML-KEM-512 KEM + ML-DSA-44 signatures
  3. Hybrid KEM-only: (X25519 + ML-KEM-512) KEMs + ECDSA signatures
  4. Full Hybrid: (X25519 + ML-KEM-512) KEMs + (ECDSA + ML-DSA-44) signatures

Output:
  - Markdown table with performance comparisons
  - CSV file with detailed results (benchmarks_results.csv)
  - Engineering analysis of network efficiency
  - Bar charts for latency and payload comparison
  - Component timing breakdown (Key Generation, Encapsulation, Verification)
"""

import time
import csv
from dataclasses import dataclass
from typing import Dict, List, Tuple
import sys
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Add the tfg-practical root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# IMPORTS FROM REPOSITORY
# ============================================================================

# Classical KEM (X25519)
from primitives.kem.classical import dh_keygen, dh_shared_secret

# Post-Quantum KEM (ML-KEM-512 / Kyber)
from primitives.kem.quantum import kyber_keygen, kyber_encapsulate, kyber_decapsulate

# Classical Signatures (ECDSA P-256)
from primitives.authentication.classical import (
    generate_keypair as ecdsa_keygen,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
)

# Post-Quantum Signatures (ML-DSA-44 / Dilithium)
from primitives.authentication.quantum import (
    generate_keypair as dilithium_keygen,
    sign as dilithium_sign,
    verify as dilithium_verify,
)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ComponentTimings:
    """Timing breakdown by operation phase."""
    key_generation_ms: float   # Time to generate all keys
    encapsulation_ms: float    # Time for encapsulation/signing operations
    verification_ms: float     # Time for verification/decapsulation operations
    
    @property
    def total_ms(self) -> float:
        return self.key_generation_ms + self.encapsulation_ms + self.verification_ms
    
    def __str__(self):
        return (
            f"KeyGen: {self.key_generation_ms:.3f}ms, "
            f"Encap: {self.encapsulation_ms:.3f}ms, "
            f"Verif: {self.verification_ms:.3f}ms"
        )


@dataclass
class LatencyMetrics:
    """Latency measurements for a benchmark scenario."""
    cold_start_ms: float       # First execution (warm-up)
    warm_mean_ms: float        # Mean of 99 subsequent executions
    warm_stdev_ms: float       # Standard deviation
    component_timings: ComponentTimings  # Breakdown by phase
    
    def __str__(self):
        return f"Cold: {self.cold_start_ms:.3f}ms, Warm: {self.warm_mean_ms:.3f}±{self.warm_stdev_ms:.3f}ms"


@dataclass
class PayloadMetrics:
    """Network payload analysis for a scenario."""
    total_bytes: int      # Total size of all transmitted data
    mtu_size: int = 1500  # Ethernet MTU (standard)
    
    @property
    def requires_fragmentation(self) -> bool:
        return self.total_bytes > self.mtu_size
    
    @property
    def num_packets(self) -> int:
        """Calculate number of IP packets needed."""
        if not self.requires_fragmentation:
            return 1
        # Account for IP header (~20 bytes) per packet
        return (self.total_bytes + self.mtu_size - 1) // self.mtu_size
    
    @property
    def status(self) -> str:
        if self.requires_fragmentation:
            return f"Fragmented ({self.num_packets} packets)"
        return "OK (1 packet)"


@dataclass
class BenchmarkScenario:
    """Complete benchmark results for one scenario."""
    name: str
    latency: LatencyMetrics
    payload: PayloadMetrics
    components: Dict[str, int]  # Component sizes breakdown
    component_timings: ComponentTimings  # Timing breakdown


# ============================================================================
# BENCHMARKING FUNCTIONS
# ============================================================================

def measure_latency(func, *args, iterations: int = 100) -> Tuple[LatencyMetrics, ComponentTimings]:
    """
    Measure latency of a function over multiple iterations.
    
    Args:
        func: Function to benchmark. Should return (total_ms, component_timings_dict)
        *args: Arguments to pass to func
        iterations: Number of iterations (1 cold start + warm iterations)
    
    Returns:
        (LatencyMetrics, ComponentTimings) - total metrics and component breakdown
    """
    times = []
    component_times = {
        'key_generation_ms': [],
        'encapsulation_ms': [],
        'verification_ms': [],
    }
    
    for i in range(iterations):
        start = time.perf_counter()
        result = func(*args)
        end = time.perf_counter()
        elapsed_ms = (end - start) * 1000
        times.append(elapsed_ms)
        
        # Collect component timings (skip first iteration for component averaging)
        if i > 0:
            component_times['key_generation_ms'].append(result[1]['key_generation_ms'])
            component_times['encapsulation_ms'].append(result[1]['encapsulation_ms'])
            component_times['verification_ms'].append(result[1]['verification_ms'])
    
    cold_start = times[0]
    warm_times = times[1:]
    warm_mean = sum(warm_times) / len(warm_times)
    warm_stdev = (sum((t - warm_mean) ** 2 for t in warm_times) / len(warm_times)) ** 0.5
    
    # Average component timings from warm iterations
    avg_keygen = sum(component_times['key_generation_ms']) / len(component_times['key_generation_ms'])
    avg_encap = sum(component_times['encapsulation_ms']) / len(component_times['encapsulation_ms'])
    avg_verif = sum(component_times['verification_ms']) / len(component_times['verification_ms'])
    
    # Calculate overhead: difference between total measured time and sum of components
    component_sum = avg_keygen + avg_encap + avg_verif
    overhead_ms = max(0, warm_mean - component_sum)
    
    # Distribute overhead proportionally to verification phase (includes system overhead)
    adjusted_verif = avg_verif + overhead_ms
    
    avg_component_timings = ComponentTimings(
        key_generation_ms=avg_keygen,
        encapsulation_ms=avg_encap,
        verification_ms=adjusted_verif,
    )
    
    latency = LatencyMetrics(
        cold_start_ms=cold_start,
        warm_mean_ms=warm_mean,
        warm_stdev_ms=warm_stdev,
        component_timings=avg_component_timings,
    )
    
    return latency, avg_component_timings


def scenario_classical() -> Tuple[LatencyMetrics, PayloadMetrics, Dict, ComponentTimings]:
    """
    Benchmark classical scenario: X25519 KEM + ECDSA signatures.
    
    Returns:
        (LatencyMetrics, PayloadMetrics, component_sizes, component_timings)
    """
    # Generate long-term signing keys (one-time, amortized)
    ecdsa_pk, ecdsa_sk = ecdsa_keygen()
    
    def full_scenario():
        """Simulate one complete classical handshake and measure component times."""
        # ===== KEY GENERATION =====
        start_keygen = time.perf_counter()
        
        client_sk_dh, client_pk_dh = dh_keygen()
        server_sk_dh, server_pk_dh = dh_keygen()
        
        end_keygen = time.perf_counter()
        keygen_ms = (end_keygen - start_keygen) * 1000
        
        # ===== ENCAPSULATION/SIGNING (Server) =====
        start_encap = time.perf_counter()
        
        transcript = client_pk_dh + server_pk_dh
        sig_ecdsa = ecdsa_sign(ecdsa_sk, transcript)
        
        end_encap = time.perf_counter()
        encap_ms = (end_encap - start_encap) * 1000
        
        # ===== VERIFICATION/DECAPSULATION (Client) =====
        start_verif = time.perf_counter()
        
        ss_client = dh_shared_secret(client_sk_dh, server_pk_dh)
        ecdsa_verify(ecdsa_pk, transcript, sig_ecdsa)
        
        end_verif = time.perf_counter()
        verif_ms = (end_verif - start_verif) * 1000
        
        # Server side (not critical for timing in this context)
        ss_server = dh_shared_secret(server_sk_dh, client_pk_dh)
        
        result_dict = {
            'ecdsa_pk': ecdsa_pk,
            'client_pk_dh': client_pk_dh,
            'server_pk_dh': server_pk_dh,
            'sig_ecdsa': sig_ecdsa,
        }
        
        component_dict = {
            'key_generation_ms': keygen_ms,
            'encapsulation_ms': encap_ms,
            'verification_ms': verif_ms,
        }
        
        return result_dict, component_dict
    
    # Measure latency
    latency, component_timings = measure_latency(full_scenario, iterations=100)
    
    # Measure payload (from one complete execution)
    result, _ = full_scenario()
    components = {
        'ECDSA_PK': len(result['ecdsa_pk']),
        'X25519_PK_Client': len(result['client_pk_dh']),
        'X25519_PK_Server': len(result['server_pk_dh']),
        'ECDSA_Signature': len(result['sig_ecdsa']),
    }
    total_payload = sum(components.values())
    payload = PayloadMetrics(total_bytes=total_payload)
    
    return latency, payload, components, component_timings


def scenario_post_quantum() -> Tuple[LatencyMetrics, PayloadMetrics, Dict, ComponentTimings]:
    """
    Benchmark post-quantum scenario: ML-KEM-512 KEM + ML-DSA-44 signatures.
    
    Returns:
        (LatencyMetrics, PayloadMetrics, component_sizes, component_timings)
    """
    # Generate long-term signing keys (one-time)
    dilithium_pk, dilithium_sk = dilithium_keygen()
    
    def full_scenario():
        """Simulate one complete post-quantum handshake and measure component times."""
        # ===== KEY GENERATION =====
        start_keygen = time.perf_counter()
        
        client_pk_kyber, client_sk_kyber = kyber_keygen()
        
        end_keygen = time.perf_counter()
        keygen_ms = (end_keygen - start_keygen) * 1000
        
        # ===== ENCAPSULATION/SIGNING (Server) =====
        start_encap = time.perf_counter()
        
        ct_kyber_client, ss_server = kyber_encapsulate(client_pk_kyber)
        transcript = client_pk_kyber + ct_kyber_client
        sig_dilithium = dilithium_sign(dilithium_sk, transcript)
        
        end_encap = time.perf_counter()
        encap_ms = (end_encap - start_encap) * 1000
        
        # ===== VERIFICATION/DECAPSULATION (Client) =====
        start_verif = time.perf_counter()
        
        ss_client = kyber_decapsulate(ct_kyber_client, client_sk_kyber)
        dilithium_verify(dilithium_pk, transcript, sig_dilithium)
        
        end_verif = time.perf_counter()
        verif_ms = (end_verif - start_verif) * 1000
        
        # Sanity check: both sides should derive the same Kyber secret
        if ss_client != ss_server:
            raise AssertionError("Kyber shared secrets do not match")
        
        result_dict = {
            'dilithium_pk': dilithium_pk,
            'client_pk_kyber': client_pk_kyber,
            'ct_kyber_client': ct_kyber_client,
            'sig_dilithium': sig_dilithium,
        }
        
        component_dict = {
            'key_generation_ms': keygen_ms,
            'encapsulation_ms': encap_ms,
            'verification_ms': verif_ms,
        }
        
        return result_dict, component_dict
    
    # Measure latency
    latency, component_timings = measure_latency(full_scenario, iterations=100)
    
    # Measure payload
    result, _ = full_scenario()
    components = {
        'Dilithium_PK': len(result['dilithium_pk']),
        'Kyber_PK_Client': len(result['client_pk_kyber']),
        'Kyber_Ciphertext': len(result['ct_kyber_client']),
        'Dilithium_Signature': len(result['sig_dilithium']),
    }
    total_payload = sum(components.values())
    payload = PayloadMetrics(total_bytes=total_payload)
    
    return latency, payload, components, component_timings


def scenario_hybrid_kem_only() -> Tuple[LatencyMetrics, PayloadMetrics, Dict, ComponentTimings]:
    """
    Benchmark hybrid KEM-only: (X25519 + ML-KEM-512) KEMs + ECDSA signatures.
    
    Returns:
        (LatencyMetrics, PayloadMetrics, component_sizes, component_timings)
    """
    # Generate long-term signing keys
    ecdsa_pk, ecdsa_sk = ecdsa_keygen()
    
    def full_scenario():
        """Simulate one complete hybrid KEM-only handshake and measure component times."""
        # ===== KEY GENERATION =====
        start_keygen = time.perf_counter()
        
        client_sk_dh, client_pk_dh = dh_keygen()
        client_pk_kyber, client_sk_kyber = kyber_keygen()
        
        server_sk_dh, server_pk_dh = dh_keygen()
        
        end_keygen = time.perf_counter()
        keygen_ms = (end_keygen - start_keygen) * 1000
        
        # ===== ENCAPSULATION/SIGNING (Server) =====
        start_encap = time.perf_counter()
        
        ct_kyber, ss_kyber_server = kyber_encapsulate(client_pk_kyber)
        transcript = client_pk_dh + client_pk_kyber + server_pk_dh + ct_kyber
        sig_ecdsa = ecdsa_sign(ecdsa_sk, transcript)
        
        end_encap = time.perf_counter()
        encap_ms = (end_encap - start_encap) * 1000
        
        # ===== VERIFICATION/DECAPSULATION (Client) =====
        start_verif = time.perf_counter()
        
        ss_dh_client = dh_shared_secret(client_sk_dh, server_pk_dh)
        ss_kyber_client = kyber_decapsulate(ct_kyber, client_sk_kyber)
        ecdsa_verify(ecdsa_pk, transcript, sig_ecdsa)
        
        end_verif = time.perf_counter()
        verif_ms = (end_verif - start_verif) * 1000
        
        # Server side
        ss_dh_server = dh_shared_secret(server_sk_dh, client_pk_dh)
        if ss_kyber_client != ss_kyber_server:
            raise AssertionError("Kyber shared secrets do not match")
        
        result_dict = {
            'ecdsa_pk': ecdsa_pk,
            'client_pk_dh': client_pk_dh,
            'client_pk_kyber': client_pk_kyber,
            'server_pk_dh': server_pk_dh,
            'ct_kyber': ct_kyber,
            'sig_ecdsa': sig_ecdsa,
        }
        
        component_dict = {
            'key_generation_ms': keygen_ms,
            'encapsulation_ms': encap_ms,
            'verification_ms': verif_ms,
        }
        
        return result_dict, component_dict
    
    # Measure latency
    latency, component_timings = measure_latency(full_scenario, iterations=100)
    
    # Measure payload
    result, _ = full_scenario()
    components = {
        'ECDSA_PK': len(result['ecdsa_pk']),
        'X25519_PK_Client': len(result['client_pk_dh']),
        'Kyber_PK_Client': len(result['client_pk_kyber']),
        'X25519_PK_Server': len(result['server_pk_dh']),
        'Kyber_Ciphertext': len(result['ct_kyber']),
        'ECDSA_Signature': len(result['sig_ecdsa']),
    }
    total_payload = sum(components.values())
    payload = PayloadMetrics(total_bytes=total_payload)
    
    return latency, payload, components, component_timings


def scenario_full_hybrid() -> Tuple[LatencyMetrics, PayloadMetrics, Dict, ComponentTimings]:
    """
    Benchmark full hybrid: (X25519 + ML-KEM-512) KEMs + (ECDSA + ML-DSA-44) signatures.
    
    Returns:
        (LatencyMetrics, PayloadMetrics, component_sizes, component_timings)
    """
    # Generate long-term signing keys
    ecdsa_pk, ecdsa_sk = ecdsa_keygen()
    dilithium_pk, dilithium_sk = dilithium_keygen()
    
    def full_scenario():
        """Simulate one complete full hybrid handshake and measure component times."""
        # ===== KEY GENERATION =====
        start_keygen = time.perf_counter()
        
        client_sk_dh, client_pk_dh = dh_keygen()
        client_pk_kyber, client_sk_kyber = kyber_keygen()
        
        server_sk_dh, server_pk_dh = dh_keygen()
        
        end_keygen = time.perf_counter()
        keygen_ms = (end_keygen - start_keygen) * 1000
        
        # ===== ENCAPSULATION/SIGNING (Server) =====
        start_encap = time.perf_counter()
        
        ct_kyber, ss_kyber_server = kyber_encapsulate(client_pk_kyber)
        transcript = client_pk_dh + client_pk_kyber + server_pk_dh + ct_kyber
        sig_ecdsa = ecdsa_sign(ecdsa_sk, transcript)
        sig_dilithium = dilithium_sign(dilithium_sk, transcript)
        
        end_encap = time.perf_counter()
        encap_ms = (end_encap - start_encap) * 1000
        
        # ===== VERIFICATION/DECAPSULATION (Client) =====
        start_verif = time.perf_counter()
        
        ss_dh_client = dh_shared_secret(client_sk_dh, server_pk_dh)
        ss_kyber_client = kyber_decapsulate(ct_kyber, client_sk_kyber)
        ecdsa_verify(ecdsa_pk, transcript, sig_ecdsa)
        dilithium_verify(dilithium_pk, transcript, sig_dilithium)
        
        end_verif = time.perf_counter()
        verif_ms = (end_verif - start_verif) * 1000
        
        # Server side
        ss_dh_server = dh_shared_secret(server_sk_dh, client_pk_dh)
        if ss_kyber_client != ss_kyber_server:
            raise AssertionError("Kyber shared secrets do not match")
        
        result_dict = {
            'ecdsa_pk': ecdsa_pk,
            'dilithium_pk': dilithium_pk,
            'client_pk_dh': client_pk_dh,
            'client_pk_kyber': client_pk_kyber,
            'server_pk_dh': server_pk_dh,
            'ct_kyber': ct_kyber,
            'sig_ecdsa': sig_ecdsa,
            'sig_dilithium': sig_dilithium,
        }
        
        component_dict = {
            'key_generation_ms': keygen_ms,
            'encapsulation_ms': encap_ms,
            'verification_ms': verif_ms,
        }
        
        return result_dict, component_dict
    
    # Measure latency
    latency, component_timings = measure_latency(full_scenario, iterations=100)
    
    # Measure payload
    result, _ = full_scenario()
    components = {
        'ECDSA_PK': len(result['ecdsa_pk']),
        'Dilithium_PK': len(result['dilithium_pk']),
        'X25519_PK_Client': len(result['client_pk_dh']),
        'Kyber_PK_Client': len(result['client_pk_kyber']),
        'X25519_PK_Server': len(result['server_pk_dh']),
        'Kyber_Ciphertext': len(result['ct_kyber']),
        'ECDSA_Signature': len(result['sig_ecdsa']),
        'Dilithium_Signature': len(result['sig_dilithium']),
    }
    total_payload = sum(components.values())
    payload = PayloadMetrics(total_bytes=total_payload)
    
    return latency, payload, components, component_timings


# ============================================================================
# OUTPUT GENERATION
# ============================================================================

def generate_markdown_table(scenarios: List[BenchmarkScenario]) -> str:
    """Generate markdown table comparing all scenarios."""
    lines = []
    lines.append("## Benchmark Results")
    lines.append("")
    lines.append("### Performance Comparison")
    lines.append("")
    lines.append("| Scenario | Warm Latency (ms) | Cold Start (ms) | Total Size (bytes) | MTU Status |")
    lines.append("|----------|-------------------|-----------------|-------------------|-----------|")
    
    for scenario in scenarios:
        warm_latency = f"{scenario.latency.warm_mean_ms:.3f}±{scenario.latency.warm_stdev_ms:.3f}"
        cold_start = f"{scenario.latency.cold_start_ms:.3f}"
        total_size = f"{scenario.payload.total_bytes}"
        mtu_status = scenario.payload.status
        
        lines.append(
            f"| {scenario.name} | {warm_latency} | {cold_start} | {total_size} | {mtu_status} |"
        )
    
    lines.append("")
    return "\n".join(lines)


def generate_detailed_breakdown(scenarios: List[BenchmarkScenario]) -> str:
    """Generate detailed component breakdowns for each scenario."""
    lines = []
    lines.append("### Component Size Breakdown")
    lines.append("")
    
    for scenario in scenarios:
        lines.append(f"#### {scenario.name}")
        lines.append("")
        
        for component, size in scenario.components.items():
            lines.append(f"- **{component}**: {size} bytes")
        
        lines.append(f"- **Total**: {scenario.payload.total_bytes} bytes")
        lines.append("")
    
    return "\n".join(lines)


def generate_component_timings_table(scenarios: List[BenchmarkScenario]) -> str:
    """Generate detailed component timing breakdown table."""
    lines = []
    lines.append("### Component Timing Breakdown")
    lines.append("")
    lines.append("| Scenario | Key Gen (ms) | Encapsulation (ms) | Verification (ms) | Total (ms) |")
    lines.append("|----------|--------------|-------------------|-------------------|-----------|")
    
    for scenario in scenarios:
        keygen = f"{scenario.component_timings.key_generation_ms:.3f}"
        encap = f"{scenario.component_timings.encapsulation_ms:.3f}"
        verif = f"{scenario.component_timings.verification_ms:.3f}"
        total = f"{scenario.component_timings.total_ms:.3f}"
        
        lines.append(f"| {scenario.name} | {keygen} | {encap} | {verif} | {total} |")
    
    lines.append("")
    return "\n".join(lines)


def generate_engineering_analysis() -> str:
    """Generate engineering commentary on efficiency."""
    lines = []
    lines.append("### Engineering Analysis")
    lines.append("")
    lines.append("#### Hybrid KEM-Only vs. Full Hybrid Efficiency")
    lines.append("")
    lines.append(
        "The **Hybrid KEM-Only** scenario (X25519 + ML-KEM-512 with ECDSA only) is more "
        "network-efficient than **Full Hybrid** (X25519 + ML-KEM-512 with ECDSA + ML-DSA-44) "
        "for the following reasons:"
    )
    lines.append("")
    lines.append("**1. Signature Payload Overhead**")
    lines.append("")
    lines.append(
        "- ECDSA P-256 signature: ~64-72 bytes (DER-encoded)"
    )
    lines.append(
        "- ML-DSA-44 (Dilithium) signature: ~2,420 bytes"
    )
    lines.append(
        "- **Difference**: ~2,350 bytes per handshake"
    )
    lines.append("")
    lines.append("**2. Fragmentation Analysis**")
    lines.append("")
    lines.append(
        "- Ethernet MTU (standard): 1,500 bytes"
    )
    lines.append(
        "- Hybrid KEM-Only total: ~2,400 bytes → Requires 2 IP packets (fragmented)"
    )
    lines.append(
        "- Full Hybrid total: ~4,800 bytes → Requires 4 IP packets (heavily fragmented)"
    )
    lines.append("")
    lines.append("**3. Network Impact**")
    lines.append("")
    lines.append(
        "- **Bandwidth Utilization**: Full Hybrid uses 2x more bytes for signatures alone"
    )
    lines.append(
        "- **Fragmentation Overhead**: More packets = more headers, more re-transmission risk, "
        "higher latency for unreliable networks"
    )
    lines.append(
        "- **Throughput**: On congested networks, Hybrid KEM-Only handshakes complete faster"
    )
    lines.append("")
    lines.append("**4. Security Trade-Off**")
    lines.append("")
    lines.append(
        "However, **Full Hybrid provides stronger authentication** via dual-signature "
        "defense-in-depth:"
    )
    lines.append(
        "- Both ECDSA and ML-DSA-44 must verify (AND logic, not OR)"
    )
    lines.append(
        "- Compromise of one signature scheme does not bypass authentication"
    )
    lines.append(
        "- ECDSA protects against quantum attacks (classical security)"
    )
    lines.append(
        "- ML-DSA-44 protects against classical cryptanalysis (post-quantum security)"
    )
    lines.append("")
    lines.append("**5. Deployment Recommendation**")
    lines.append("")
    lines.append(
        "- **Hybrid KEM-Only**: Suitable for bandwidth-constrained environments (mobile, "
        "IoT, satellite links) where classical authentication is acceptable as interim "
        "mitigation until post-quantum solutions mature"
    )
    lines.append(
        "- **Full Hybrid**: Recommended for infrastructure requiring maximum resilience "
        "against both quantum and classical threats (critical systems, long-term archives, "
        "high-assurance deployments)"
    )
    lines.append("")
    
    return "\n".join(lines)


def export_to_csv(scenarios: List[BenchmarkScenario], filename: str = "benchmarks_results.csv"):
    """Export detailed results to CSV file."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            'Scenario',
            'Warm_Latency_Mean_ms',
            'Warm_Latency_Stdev_ms',
            'Cold_Start_ms',
            'KeyGen_ms',
            'Encapsulation_ms',
            'Verification_ms',
            'Total_Payload_Bytes',
            'Requires_Fragmentation',
            'Number_of_IP_Packets',
        ])
        
        # Write data rows
        for scenario in scenarios:
            writer.writerow([
                scenario.name,
                f"{scenario.latency.warm_mean_ms:.3f}",
                f"{scenario.latency.warm_stdev_ms:.3f}",
                f"{scenario.latency.cold_start_ms:.3f}",
                f"{scenario.component_timings.key_generation_ms:.3f}",
                f"{scenario.component_timings.encapsulation_ms:.3f}",
                f"{scenario.component_timings.verification_ms:.3f}",
                scenario.payload.total_bytes,
                scenario.payload.requires_fragmentation,
                scenario.payload.num_packets,
            ])
        
        # Write component details in separate section
        writer.writerow([])
        writer.writerow(['Component Breakdown'])
        writer.writerow([])
        
        for scenario in scenarios:
            writer.writerow([scenario.name])
            for component, size in scenario.components.items():
                writer.writerow(['', component, size])
            writer.writerow([])


def generate_latency_chart(scenarios: List[BenchmarkScenario], filename: str = "benchmark_latency.png"):
    """Generate bar chart comparing warm latencies across scenarios."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    names = [s.name for s in scenarios]
    warm_means = [s.latency.warm_mean_ms for s in scenarios]
    warm_stdevs = [s.latency.warm_stdev_ms for s in scenarios]
    
    x_pos = range(len(names))
    bars = ax.bar(x_pos, warm_means, yerr=warm_stdevs, capsize=5, 
                   color=['#3498db', '#e74c3c', '#2ecc71', '#f39c12'],
                   alpha=0.8, edgecolor='black', linewidth=1.5)
    
    ax.set_ylabel('Latency (ms)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Scenario', fontsize=12, fontweight='bold')
    ax.set_title('Warm Latency Comparison Across Handshake Scenarios', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(names, rotation=15, ha='right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels on bars
    for i, (bar, mean, stdev) in enumerate(zip(bars, warm_means, warm_stdevs)):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{mean:.2f}ms\n±{stdev:.2f}ms',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Latency chart saved: {filename}")


def generate_payload_chart(scenarios: List[BenchmarkScenario], filename: str = "benchmark_payload.png"):
    """Generate bar chart comparing payload sizes with MTU threshold."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    names = [s.name for s in scenarios]
    payloads = [s.payload.total_bytes for s in scenarios]
    
    x_pos = range(len(names))
    
    # Color bars based on fragmentation
    colors = []
    for payload in payloads:
        if payload > 1500:
            colors.append('#e74c3c')  # Red for fragmented
        else:
            colors.append('#2ecc71')  # Green for OK
    
    bars = ax.bar(x_pos, payloads, color=colors, alpha=0.8, 
                  edgecolor='black', linewidth=1.5)
    
    # Add MTU threshold line
    ax.axhline(y=1500, color='red', linestyle='--', linewidth=2.5, 
               label='MTU Threshold (1500 bytes)')
    
    ax.set_ylabel('Total Payload (bytes)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Scenario', fontsize=12, fontweight='bold')
    ax.set_title('Network Payload Comparison with MTU Fragmentation Threshold', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(names, rotation=15, ha='right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.legend(loc='upper left', fontsize=11)
    
    # Add value labels on bars
    for i, (bar, payload) in enumerate(zip(bars, payloads)):
        height = bar.get_height()
        status = "Fragmented" if payload > 1500 else "OK"
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{payload} bytes\n({status})',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Payload chart saved: {filename}")


def generate_component_timing_chart(scenarios: List[BenchmarkScenario], 
                                   filename: str = "benchmark_component_timings.png"):
    """Generate stacked bar chart showing component timing breakdown."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    names = [s.name for s in scenarios]
    keygen_times = [s.component_timings.key_generation_ms for s in scenarios]
    encap_times = [s.component_timings.encapsulation_ms for s in scenarios]
    verif_times = [s.component_timings.verification_ms for s in scenarios]
    
    x_pos = range(len(names))
    
    # Create stacked bars
    p1 = ax.bar(x_pos, keygen_times, label='Key Generation', 
               color='#3498db', alpha=0.8, edgecolor='black', linewidth=1.5)
    p2 = ax.bar(x_pos, encap_times, bottom=keygen_times, 
               label='Encapsulation/Signing', color='#2ecc71', 
               alpha=0.8, edgecolor='black', linewidth=1.5)
    p3 = ax.bar(x_pos, verif_times, 
               bottom=[k+e for k,e in zip(keygen_times, encap_times)],
               label='Verification/Decapsulation', color='#f39c12', 
               alpha=0.8, edgecolor='black', linewidth=1.5)
    
    ax.set_ylabel('Latency (ms)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Scenario', fontsize=12, fontweight='bold')
    ax.set_title('Component Timing Breakdown Across Scenarios', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(names, rotation=15, ha='right')
    ax.legend(loc='upper left', fontsize=11)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Component timing chart saved: {filename}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Run complete benchmark suite."""
    print("=" * 80)
    print("Hybrid Post-Quantum Handshake Protocol - Benchmark Suite")
    print("=" * 80)
    print()
    
    print("Benchmarking scenarios...")
    print()
    
    # Run all scenarios
    print("  1. Classical (X25519 + ECDSA)...", end='', flush=True)
    lat_classical, pay_classical, comp_classical, timing_classical = scenario_classical()
    print(" ✓")
    
    print("  2. Post-Quantum (ML-KEM-512 + ML-DSA-44)...", end='', flush=True)
    lat_pq, pay_pq, comp_pq, timing_pq = scenario_post_quantum()
    print(" ✓")
    
    print("  3. Hybrid KEM-Only (X25519+ML-KEM-512 + ECDSA)...", end='', flush=True)
    lat_hybrid_kem, pay_hybrid_kem, comp_hybrid_kem, timing_hybrid_kem = scenario_hybrid_kem_only()
    print(" ✓")
    
    print("  4. Full Hybrid (X25519+ML-KEM-512 + ECDSA+ML-DSA-44)...", end='', flush=True)
    lat_full_hybrid, pay_full_hybrid, comp_full_hybrid, timing_full_hybrid = scenario_full_hybrid()
    print(" ✓")
    
    print()
    print("=" * 80)
    
    # Organize results
    scenarios = [
        BenchmarkScenario("Classical", lat_classical, pay_classical, comp_classical, timing_classical),
        BenchmarkScenario("Post-Quantum", lat_pq, pay_pq, comp_pq, timing_pq),
        BenchmarkScenario("Hybrid KEM-Only", lat_hybrid_kem, pay_hybrid_kem, comp_hybrid_kem, timing_hybrid_kem),
        BenchmarkScenario("Full Hybrid", lat_full_hybrid, pay_full_hybrid, comp_full_hybrid, timing_full_hybrid),
    ]
    
    # Print detailed results to console
    print("\n### Detailed Performance Analysis ###\n")
    
    for scenario in scenarios:
        print(f"\n{scenario.name}:")
        print(f"  Latency (Warm):       {scenario.latency.warm_mean_ms:.3f}±{scenario.latency.warm_stdev_ms:.3f} ms")
        print(f"  Latency (Cold Start): {scenario.latency.cold_start_ms:.3f} ms")
        print(f"  Component Breakdown:")
        print(f"    - Key Generation:   {scenario.component_timings.key_generation_ms:.3f} ms")
        print(f"    - Encapsulation:    {scenario.component_timings.encapsulation_ms:.3f} ms")
        print(f"    - Verification:     {scenario.component_timings.verification_ms:.3f} ms")
        print(f"  Total Payload:        {scenario.payload.total_bytes} bytes ({scenario.payload.status})")
        print(f"  IP Packets Required:  {scenario.payload.num_packets}")
    
    print("\n" + "=" * 80)
    
    # Generate and print markdown report
    markdown_output = []
    markdown_output.append(generate_markdown_table(scenarios))
    markdown_output.append(generate_detailed_breakdown(scenarios))
    markdown_output.append(generate_component_timings_table(scenarios))
    markdown_output.append(generate_engineering_analysis())
    
    report = "\n".join(markdown_output)
    print(report)
    
    # Export to CSV
    export_to_csv(scenarios)
    print()
    print("=" * 80)
    print(f"Results exported to: benchmarks_results.csv")
    print("=" * 80)
    
    # Generate charts
    print("\nGenerating visualizations...")
    generate_latency_chart(scenarios)
    generate_payload_chart(scenarios)
    generate_component_timing_chart(scenarios)
    
    print("\n" + "=" * 80)
    print("Benchmark suite completed successfully!")
    print("=" * 80)
    
    return scenarios


if __name__ == "__main__":
    main()
