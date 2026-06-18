#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import math
import os
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple


DEFAULT_FIELDS = [
    "frame.time_epoch",
    "frame.number",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.window_size_value",
    "tcp.window_size",
    "tcp.window_size_scalefactor",
    "tcp.options.wscale.shift",
    "tcp.options.mss_val",
    "tcp.options.timestamp.tsval",
    "tcp.options.timestamp.tsecr",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.bytes_in_flight",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "tcp.analysis.window_full",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_update",
    "tcp.analysis.partial_ack",
    "tcp.options.sack_perm",
]

EVENT_FIELDS = {
    "retransmission": "tcp.analysis.retransmission",
    "fast_retransmission": "tcp.analysis.fast_retransmission",
    "spurious_retransmission": "tcp.analysis.spurious_retransmission",
    "duplicate_ack": "tcp.analysis.duplicate_ack",
    "out_of_order": "tcp.analysis.out_of_order",
    "lost_segment": "tcp.analysis.lost_segment",
    "window_full": "tcp.analysis.window_full",
    "zero_window": "tcp.analysis.zero_window",
    "window_update": "tcp.analysis.window_update",
    "partial_ack": "tcp.analysis.partial_ack",
}


@dataclass(frozen=True)
class FlowKey:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    def flow_id(self) -> str:
        return f"{self.local_ip}:{self.local_port}-{self.remote_ip}:{self.remote_port}"


@dataclass
class PacketRecord:
    ts: float
    frame_number: int
    ip_src: str
    ip_dst: str
    sport: int
    dport: int
    stream: Optional[int]
    syn: bool
    ack_flag: bool
    fin: bool
    rst: bool
    seq: int
    ack: int
    tcp_len: int
    win_raw: Optional[int]
    win_calc: Optional[int]
    wscale_shift: Optional[int]
    mss: Optional[int]
    tsval: Optional[int]
    tsecr: Optional[int]
    ack_rtt: Optional[float]
    ws_bytes_in_flight: Optional[int]
    events: Dict[str, bool]
    sack_perm: bool


@dataclass
class IntervalStats:
    window_start: float
    window_size_ms: int
    payload_tx_bytes: int = 0
    ack_progress_bytes: int = 0
    wire_tx_bits_est: int = 0
    bytes_in_flight_samples: List[int] = field(default_factory=list)
    peer_rwnd_bytes_samples: List[int] = field(default_factory=list)
    peer_rwnd_headroom_samples: List[int] = field(default_factory=list)
    rwnd_utilization_samples: List[float] = field(default_factory=list)
    ack_rtt_samples_ms: List[float] = field(default_factory=list)
    ts_rtt_samples_ms: List[float] = field(default_factory=list)
    event_counts: Counter = field(default_factory=Counter)
    sender_active_samples: int = 0
    sample_count: int = 0


@dataclass
class EventRecord:
    flow_id: str
    tcp_stream: Optional[int]
    ts: float
    frame_number: int
    event_type: str
    direction: str
    seq: int
    ack: int
    tcp_len: int
    note: str


@dataclass
class FlowState:
    key: FlowKey
    tcp_stream: Optional[int]
    first_ts: float
    last_ts: float
    local_role: str = "unknown"
    handshake_complete: bool = False
    analysis_level: str = "reduced"
    capture_position: str = "near_sender"
    syn_time: Optional[float] = None
    synack_time: Optional[float] = None
    ack_time: Optional[float] = None
    rtt_handshake_ms: Optional[float] = None
    mss_local: Optional[int] = None
    mss_remote: Optional[int] = None
    wscale_local: Optional[int] = None
    wscale_remote: Optional[int] = None
    sack_permitted_local: bool = False
    sack_permitted_remote: bool = False
    tsopt_present_local: bool = False
    tsopt_present_remote: bool = False
    highest_seq_sent_local: int = 0
    highest_acked_by_peer: int = 0
    peer_rwnd_raw: Optional[int] = None
    peer_rwnd_bytes: Optional[int] = None
    peer_rwnd_headroom: Optional[int] = None
    retransmitted_payload_bytes: int = 0
    total_payload_tx_bytes: int = 0
    payload_wire_bits_est: int = 0
    duplicate_ack_packets: int = 0
    retransmission_packets: int = 0
    fast_retransmission_packets: int = 0
    spurious_retransmission_packets: int = 0
    out_of_order_packets: int = 0
    lost_segment_events: int = 0
    partial_ack_events: int = 0
    window_full_events: int = 0
    zero_window_events: int = 0
    window_update_events: int = 0
    loss_episode_count: int = 0
    sender_active_time_windows: int = 0
    alp_time_windows: int = 0
    classification: str = "unknown"
    classification_confidence: float = 0.0
    classification_profile: str = "baseline"
    classification_reasons: List[str] = field(default_factory=list)
    supporting_metrics: Dict[str, float] = field(default_factory=dict)
    ack_rtt_samples_ms: List[float] = field(default_factory=list)
    ts_rtt_samples_ms: List[float] = field(default_factory=list)
    timestamps_map: Dict[int, float] = field(default_factory=dict)
    events: List[EventRecord] = field(default_factory=list)
    interval_stats: Dict[int, Dict[int, IntervalStats]] = field(default_factory=lambda: {100: {}, 1000: {}})


DEFAULT_CONFIG = {
    "local_networks": ["10.1.1.0/24"],
    "line_rate_bps": 25_000_000_000,
    "window_sizes_ms": [100, 1000],
    "flow_min_duration_ms": 1,
    "flow_min_payload_bytes": 1,
    "baseline_thresholds": {
        "rwnd_headroom_mss_multiplier": 3.0,
        "dispersion_low": 0.20,
        "retransmission_high": 0.02,
        "receiver_limitation_high": 0.30,
        "burstiness_high": 0.50,
        "alp_idle_seconds": 5.0,
    },
    "tuned_thresholds": {},
}


def load_config(path: Optional[str]) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if not path:
        return cfg
    with open(path, "r", encoding="utf-8") as fh:
        user_cfg = json.load(fh)
    merge_dict(cfg, user_cfg)
    return cfg


def merge_dict(base: dict, other: dict) -> None:
    for k, v in other.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge_dict(base[k], v)
        else:
            base[k] = v


def to_bool(val: Optional[str]) -> bool:
    if val is None:
        return False
    return str(val).strip().lower() not in ("", "0", "false", "no")


def to_int(val: Optional[str]) -> Optional[int]:
    if val is None or str(val).strip() == "":
        return None
    try:
        return int(float(val))
    except ValueError:
        return None


def to_float(val: Optional[str]) -> Optional[float]:
    if val is None or str(val).strip() == "":
        return None
    try:
        return float(val)
    except ValueError:
        return None


def run_tshark(pcap: str, out_csv: str) -> None:
    cmd = ["tshark", "-r", pcap, "-Y", "tcp", "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for field in DEFAULT_FIELDS:
        cmd.extend(["-e", field])
    with open(out_csv, "w", encoding="utf-8", newline="") as fh:
        subprocess.run(cmd, stdout=fh, check=True)


def parse_packet(row: dict) -> Optional[PacketRecord]:
    ip_src = row.get("ip.src")
    ip_dst = row.get("ip.dst")
    if not ip_src or not ip_dst:
        return None
    events = {name: to_bool(row.get(field)) for name, field in EVENT_FIELDS.items()}
    return PacketRecord(
        ts=to_float(row.get("frame.time_epoch")) or 0.0,
        frame_number=to_int(row.get("frame.number")) or 0,
        ip_src=ip_src,
        ip_dst=ip_dst,
        sport=to_int(row.get("tcp.srcport")) or 0,
        dport=to_int(row.get("tcp.dstport")) or 0,
        stream=to_int(row.get("tcp.stream")),
        syn=to_bool(row.get("tcp.flags.syn")),
        ack_flag=to_bool(row.get("tcp.flags.ack")),
        fin=to_bool(row.get("tcp.flags.fin")),
        rst=to_bool(row.get("tcp.flags.reset")),
        seq=to_int(row.get("tcp.seq")) or 0,
        ack=to_int(row.get("tcp.ack")) or 0,
        tcp_len=to_int(row.get("tcp.len")) or 0,
        win_raw=to_int(row.get("tcp.window_size_value")),
        win_calc=to_int(row.get("tcp.window_size")),
        wscale_shift=to_int(row.get("tcp.options.wscale.shift")),
        mss=to_int(row.get("tcp.options.mss_val")),
        tsval=to_int(row.get("tcp.options.timestamp.tsval")),
        tsecr=to_int(row.get("tcp.options.timestamp.tsecr")),
        ack_rtt=to_float(row.get("tcp.analysis.ack_rtt")),
        ws_bytes_in_flight=to_int(row.get("tcp.analysis.bytes_in_flight")),
        events=events,
        sack_perm=to_bool(row.get("tcp.options.sack_perm")),
    )


def is_local(ip: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)


def flow_key_from_packet(pkt: PacketRecord, networks: List[ipaddress._BaseNetwork]) -> Optional[FlowKey]:
    src_local = is_local(pkt.ip_src, networks)
    dst_local = is_local(pkt.ip_dst, networks)
    if src_local == dst_local:
        return None
    if src_local:
        return FlowKey(pkt.ip_src, pkt.sport, pkt.ip_dst, pkt.dport)
    return FlowKey(pkt.ip_dst, pkt.dport, pkt.ip_src, pkt.sport)


def get_interval_bucket(ts: float, window_ms: int) -> int:
    return int(ts * 1000 // window_ms)


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    vals = sorted(values)
    if len(vals) == 1:
        return vals[0]
    k = (len(vals) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return vals[int(k)]
    d0 = vals[f] * (c - k)
    d1 = vals[c] * (k - f)
    return d0 + d1


def mean_or_none(values: List[float]) -> Optional[float]:
    return statistics.mean(values) if values else None


def classify_flow(flow: FlowState, cfg: dict) -> None:
    th = cfg.get("baseline_thresholds", {}) if flow.classification_profile == "baseline" else cfg.get("tuned_thresholds", {})
    disp_low = th.get("dispersion_low", 0.20)
    retr_high = th.get("retransmission_high", 0.02)
    recv_high = th.get("receiver_limitation_high", 0.30)
    burst_high = th.get("burstiness_high", 0.50)

    total_duration = max(flow.last_ts - flow.first_ts, 0.000001)
    throughput_bps = (flow.total_payload_tx_bytes * 8) / total_duration
    line_rate_bps = cfg.get("line_rate_bps", 25_000_000_000)
    wire_pct = flow.payload_wire_bits_est / max(total_duration * line_rate_bps, 1)

    retrans_score = 0.0
    if flow.total_payload_tx_bytes > 0:
        retrans_score = flow.retransmitted_payload_bytes / flow.total_payload_tx_bytes

    receiver_limitation_score = compute_receiver_limitation_score(flow)
    burstiness_score = compute_burstiness_score(flow)
    dispersion_score = max(0.0, 1.0 - min(throughput_bps / line_rate_bps, 1.0))

    flow.supporting_metrics = {
        "throughput_bps": throughput_bps,
        "wire_pct_of_25g_mean_est": wire_pct,
        "retransmission_score": retrans_score,
        "receiver_window_limitation_score": receiver_limitation_score,
        "burstiness_score": burstiness_score,
        "dispersion_score": dispersion_score,
    }

    reasons = []
    confidence = 0.45
    classification = "unknown"

    if dispersion_score < disp_low:
        classification = "unshared_bottleneck"
        reasons.append("low_dispersion_score")
        confidence = 0.65
    elif retrans_score > retr_high:
        classification = "shared_bottleneck"
        reasons.append("high_retransmission_score")
        confidence = 0.75
    elif receiver_limitation_score > recv_high:
        classification = "receiver_limitation"
        reasons.append("low_rwnd_headroom")
        if flow.window_full_events:
            reasons.append("repeated_window_full")
        if flow.zero_window_events:
            reasons.append("zero_window_seen")
        confidence = 0.80
    elif burstiness_score > burst_high and retrans_score <= retr_high and receiver_limitation_score <= recv_high:
        classification = "transport_limitation"
        reasons.append("high_burstiness_low_loss")
        confidence = 0.60
    else:
        classification = "mixed_or_unknown"
        confidence = 0.40

    if not flow.handshake_complete:
        classification = "reduced_no_full_handshake"
        confidence = min(confidence, 0.30)
        reasons.append("incomplete_handshake")

    flow.classification = classification
    flow.classification_confidence = confidence
    flow.classification_reasons = reasons


def compute_receiver_limitation_score(flow: FlowState) -> float:
    samples = []
    for stats_by_bucket in flow.interval_stats.values():
        for bucket in stats_by_bucket.values():
            for idx, headroom in enumerate(bucket.peer_rwnd_headroom_samples):
                rwnd = bucket.peer_rwnd_bytes_samples[idx] if idx < len(bucket.peer_rwnd_bytes_samples) else None
                bif = bucket.bytes_in_flight_samples[idx] if idx < len(bucket.bytes_in_flight_samples) else None
                if rwnd is None or bif is None:
                    continue
                if rwnd <= 0:
                    continue
                samples.append(1.0 if headroom <= max(3 * (flow.mss_local or 1460), 1) else 0.0)
    return mean_or_none(samples) or 0.0


def compute_burstiness_score(flow: FlowState) -> float:
    intervals = []
    for bucket in flow.interval_stats.get(100, {}).values():
        intervals.append(bucket.payload_tx_bytes)
    if not intervals:
        return 0.0
    mu = statistics.mean(intervals)
    if mu == 0:
        return 0.0
    sigma = statistics.pstdev(intervals)
    return min(sigma / mu, 1.0)


def update_handshake(flow: FlowState, pkt: PacketRecord) -> None:
    from_local = pkt.ip_src == flow.key.local_ip and pkt.sport == flow.key.local_port
    if pkt.syn and not pkt.ack_flag and from_local:
        flow.syn_time = flow.syn_time or pkt.ts
        flow.local_role = "initiator"
        flow.mss_local = flow.mss or flow.mss_local
        flow.wscale_local = pkt.wscale_shift if pkt.wscale_shift is not None else flow.wscale_local
        flow.sack_permitted_local = flow.sack_permitted_local or pkt.sack_perm
        flow.tsopt_present_local = flow.tsopt_present_local or (pkt.tsval is not None)
    elif pkt.syn and pkt.ack_flag and not from_local:
        flow.synack_time = flow.synack_time or pkt.ts
        flow.mss_remote = pkt.mss or flow.mss_remote
        flow.wscale_remote = pkt.wscale_shift if pkt.wscale_shift is not None else flow.wscale_remote
        flow.sack_permitted_remote = flow.sack_permitted_remote or pkt.sack_perm
        flow.tsopt_present_remote = flow.tsopt_present_remote or (pkt.tsval is not None)
    elif pkt.ack_flag and not pkt.syn and from_local and flow.syn_time and flow.synack_time and flow.ack_time is None:
        flow.ack_time = pkt.ts
        flow.handshake_complete = True
        flow.analysis_level = "full_rca"
        flow.rtt_handshake_ms = (flow.synack_time - flow.syn_time) * 1000.0


def estimate_wire_bits(pkt: PacketRecord) -> int:
    if pkt.tcp_len <= 0:
        return 0
    l2_l3_l4_overhead = 14 + 20 + 20 + 4 + 8 + 12
    return (pkt.tcp_len + l2_l3_l4_overhead) * 8


def add_interval_sample(flow: FlowState, pkt: PacketRecord, from_local: bool) -> None:
    for window_ms in (100, 1000):
        bucket_id = get_interval_bucket(pkt.ts, window_ms)
        stats = flow.interval_stats[window_ms].get(bucket_id)
        if not stats:
            stats = IntervalStats(window_start=(bucket_id * window_ms) / 1000.0, window_size_ms=window_ms)
            flow.interval_stats[window_ms][bucket_id] = stats
        stats.sample_count += 1

        if flow.peer_rwnd_bytes is not None:
            stats.peer_rwnd_bytes_samples.append(flow.peer_rwnd_bytes)
        if flow.peer_rwnd_headroom is not None:
            stats.peer_rwnd_headroom_samples.append(flow.peer_rwnd_headroom)
        if flow.highest_seq_sent_local and flow.highest_acked_by_peer >= 0:
            bif = max(flow.highest_seq_sent_local - flow.highest_acked_by_peer, 0)
            stats.bytes_in_flight_samples.append(bif)
            if flow.peer_rwnd_bytes and flow.peer_rwnd_bytes > 0:
                stats.rwnd_utilization_samples.append(min(bif / flow.peer_rwnd_bytes, 10.0))
        if pkt.ack_rtt is not None:
            ms = pkt.ack_rtt * 1000.0
            stats.ack_rtt_samples_ms.append(ms)
        ts_rtt = derive_timestamp_rtt(flow, pkt)
        if ts_rtt is not None:
            stats.ts_rtt_samples_ms.append(ts_rtt)
        for ev, present in pkt.events.items():
            if present:
                stats.event_counts[ev] += 1
        if from_local and pkt.tcp_len > 0:
            stats.payload_tx_bytes += pkt.tcp_len
            stats.wire_tx_bits_est += estimate_wire_bits(pkt)
            stats.sender_active_samples += 1
        if (not from_local) and pkt.ack_flag and pkt.ack > flow.highest_acked_by_peer:
            stats.ack_progress_bytes += pkt.ack - flow.highest_acked_by_peer


def derive_timestamp_rtt(flow: FlowState, pkt: PacketRecord) -> Optional[float]:
    from_local = pkt.ip_src == flow.key.local_ip and pkt.sport == flow.key.local_port
    if from_local and pkt.tsval is not None:
        flow.timestamps_map[pkt.tsval] = pkt.ts
        return None
    if (not from_local) and pkt.tsecr is not None:
        sent_ts = flow.timestamps_map.get(pkt.tsecr)
        if sent_ts is not None and pkt.ts >= sent_ts:
            rtt_ms = (pkt.ts - sent_ts) * 1000.0
            flow.ts_rtt_samples_ms.append(rtt_ms)
            return rtt_ms
    return None


def record_event(flow: FlowState, pkt: PacketRecord, event_type: str, direction: str, note: str = "") -> None:
    flow.events.append(EventRecord(
        flow_id=flow.key.flow_id(),
        tcp_stream=flow.tcp_stream,
        ts=pkt.ts,
        frame_number=pkt.frame_number,
        event_type=event_type,
        direction=direction,
        seq=pkt.seq,
        ack=pkt.ack,
        tcp_len=pkt.tcp_len,
        note=note,
    ))


def process_packets(csv_path: str, cfg: dict) -> Tuple[Dict[FlowKey, FlowState], dict]:
    networks = [ipaddress.ip_network(n) for n in cfg.get("local_networks", [])]
    flows: Dict[FlowKey, FlowState] = {}
    meta = {"packet_count": 0, "flow_count": 0, "full_rca_flows": 0, "reduced_flows": 0}

    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            pkt = parse_packet(row)
            if not pkt:
                continue
            meta["packet_count"] += 1
            key = flow_key_from_packet(pkt, networks)
            if not key:
                continue
            flow = flows.get(key)
            if not flow:
                flow = FlowState(key=key, tcp_stream=pkt.stream, first_ts=pkt.ts, last_ts=pkt.ts)
                flows[key] = flow
            flow.last_ts = pkt.ts
            from_local = pkt.ip_src == flow.key.local_ip and pkt.sport == flow.key.local_port
            direction = "local_to_remote" if from_local else "remote_to_local"

            update_handshake(flow, pkt)

            if pkt.ack_rtt is not None:
                flow.ack_rtt_samples_ms.append(pkt.ack_rtt * 1000.0)

            if from_local and pkt.tcp_len > 0:
                next_seq = pkt.seq + pkt.tcp_len
                flow.total_payload_tx_bytes += pkt.tcp_len
                flow.payload_wire_bits_est += estimate_wire_bits(pkt)
                if next_seq > flow.highest_seq_sent_local:
                    flow.highest_seq_sent_local = next_seq
            elif (not from_local) and pkt.ack_flag:
                if pkt.ack > flow.highest_acked_by_peer:
                    flow.highest_acked_by_peer = pkt.ack
                if pkt.win_raw is not None:
                    flow.peer_rwnd_raw = pkt.win_raw
                    scale = flow.wscale_remote or 0
                    flow.peer_rwnd_bytes = pkt.win_raw << scale
                    if flow.highest_seq_sent_local >= flow.highest_acked_by_peer:
                        flow.peer_rwnd_headroom = flow.peer_rwnd_bytes - (flow.highest_seq_sent_local - flow.highest_acked_by_peer)

            for ev_name, present in pkt.events.items():
                if present:
                    record_event(flow, pkt, ev_name, direction)
                    if ev_name == "retransmission":
                        flow.retransmission_packets += 1
                        flow.retransmitted_payload_bytes += pkt.tcp_len
                    elif ev_name == "fast_retransmission":
                        flow.fast_retransmission_packets += 1
                        flow.retransmitted_payload_bytes += pkt.tcp_len
                    elif ev_name == "spurious_retransmission":
                        flow.spurious_retransmission_packets += 1
                    elif ev_name == "duplicate_ack":
                        flow.duplicate_ack_packets += 1
                    elif ev_name == "out_of_order":
                        flow.out_of_order_packets += 1
                    elif ev_name == "lost_segment":
                        flow.lost_segment_events += 1
                    elif ev_name == "partial_ack":
                        flow.partial_ack_events += 1
                    elif ev_name == "window_full":
                        flow.window_full_events += 1
                    elif ev_name == "zero_window":
                        flow.zero_window_events += 1
                    elif ev_name == "window_update":
                        flow.window_update_events += 1

            add_interval_sample(flow, pkt, from_local)

    for flow in flows.values():
        if flow.handshake_complete:
            flow.analysis_level = "full_rca"
            meta["full_rca_flows"] += 1
        else:
            meta["reduced_flows"] += 1
        classify_flow(flow, cfg)
    meta["flow_count"] = len(flows)
    return flows, meta


def flow_summary_row(flow: FlowState, cfg: dict) -> dict:
    duration_s = max(flow.last_ts - flow.first_ts, 0.000001)
    throughput_bps = (flow.total_payload_tx_bytes * 8) / duration_s
    wire_pct = flow.payload_wire_bits_est / max(duration_s * cfg.get("line_rate_bps", 25_000_000_000), 1)
    return {
        "flow_id": flow.key.flow_id(),
        "tcp_stream": flow.tcp_stream,
        "local_ip": flow.key.local_ip,
        "local_port": flow.key.local_port,
        "remote_ip": flow.key.remote_ip,
        "remote_port": flow.key.remote_port,
        "local_role": flow.local_role,
        "analysis_level": flow.analysis_level,
        "capture_position": flow.capture_position,
        "handshake_complete": flow.handshake_complete,
        "rtt_handshake_ms": flow.rtt_handshake_ms,
        "ack_rtt_mean_ms": mean_or_none(flow.ack_rtt_samples_ms),
        "ack_rtt_p95_ms": percentile(flow.ack_rtt_samples_ms, 0.95),
        "ts_rtt_mean_ms": mean_or_none(flow.ts_rtt_samples_ms),
        "ts_rtt_p95_ms": percentile(flow.ts_rtt_samples_ms, 0.95),
        "mss_local": flow.mss_local,
        "mss_remote": flow.mss_remote,
        "wscale_local": flow.wscale_local,
        "wscale_remote": flow.wscale_remote,
        "sack_permitted_local": flow.sack_permitted_local,
        "sack_permitted_remote": flow.sack_permitted_remote,
        "total_payload_tx_bytes": flow.total_payload_tx_bytes,
        "throughput_bps": throughput_bps,
        "wire_pct_of_25g_mean_est": wire_pct,
        "peer_rwnd_bytes_last": flow.peer_rwnd_bytes,
        "bytes_in_flight_last": max(flow.highest_seq_sent_local - flow.highest_acked_by_peer, 0),
        "retransmission_packets": flow.retransmission_packets,
        "fast_retransmission_packets": flow.fast_retransmission_packets,
        "spurious_retransmission_packets": flow.spurious_retransmission_packets,
        "duplicate_ack_packets": flow.duplicate_ack_packets,
        "out_of_order_packets": flow.out_of_order_packets,
        "lost_segment_events": flow.lost_segment_events,
        "partial_ack_events": flow.partial_ack_events,
        "window_full_events": flow.window_full_events,
        "zero_window_events": flow.zero_window_events,
        "window_update_events": flow.window_update_events,
        "retransmission_score": flow.supporting_metrics.get("retransmission_score"),
        "receiver_window_limitation_score": flow.supporting_metrics.get("receiver_window_limitation_score"),
        "burstiness_score": flow.supporting_metrics.get("burstiness_score"),
        "dispersion_score": flow.supporting_metrics.get("dispersion_score"),
        "classification": flow.classification,
        "classification_confidence": flow.classification_confidence,
        "classification_profile": flow.classification_profile,
        "classification_reasons": ";".join(flow.classification_reasons),
    }


def write_csv(path: str, rows: List[dict]) -> None:
    if not rows:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("")
        return
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def build_interval_rows(flows: Dict[FlowKey, FlowState], cfg: dict, window_ms: int) -> List[dict]:
    rows = []
    for flow in flows.values():
        for bucket_id, stats in sorted(flow.interval_stats[window_ms].items()):
            duration_s = window_ms / 1000.0
            rows.append({
                "flow_id": flow.key.flow_id(),
                "tcp_stream": flow.tcp_stream,
                "window_start": stats.window_start,
                "window_size_ms": window_ms,
                "payload_tx_bytes": stats.payload_tx_bytes,
                "payload_tx_bps": (stats.payload_tx_bytes * 8) / duration_s,
                "wire_tx_bits_est": stats.wire_tx_bits_est,
                "wire_pct_of_25g": stats.wire_tx_bits_est / max(duration_s * cfg.get("line_rate_bps", 25_000_000_000), 1),
                "ack_progress_bytes": stats.ack_progress_bytes,
                "mean_bytes_in_flight": mean_or_none(stats.bytes_in_flight_samples),
                "max_bytes_in_flight": max(stats.bytes_in_flight_samples) if stats.bytes_in_flight_samples else None,
                "mean_peer_rwnd_bytes": mean_or_none(stats.peer_rwnd_bytes_samples),
                "min_peer_rwnd_headroom": min(stats.peer_rwnd_headroom_samples) if stats.peer_rwnd_headroom_samples else None,
                "rwnd_utilization_mean": mean_or_none(stats.rwnd_utilization_samples),
                "ack_rtt_mean_ms": mean_or_none(stats.ack_rtt_samples_ms),
                "ack_rtt_p95_ms": percentile(stats.ack_rtt_samples_ms, 0.95),
                "ts_rtt_mean_ms": mean_or_none(stats.ts_rtt_samples_ms),
                "ts_rtt_p95_ms": percentile(stats.ts_rtt_samples_ms, 0.95),
                "retransmission_packets": stats.event_counts.get("retransmission", 0),
                "fast_retransmission_packets": stats.event_counts.get("fast_retransmission", 0),
                "spurious_retransmission_packets": stats.event_counts.get("spurious_retransmission", 0),
                "duplicate_ack_packets": stats.event_counts.get("duplicate_ack", 0),
                "out_of_order_packets": stats.event_counts.get("out_of_order", 0),
                "lost_segment_events": stats.event_counts.get("lost_segment", 0),
                "window_full_events": stats.event_counts.get("window_full", 0),
                "zero_window_events": stats.event_counts.get("zero_window", 0),
                "window_update_events": stats.event_counts.get("window_update", 0),
                "partial_ack_events": stats.event_counts.get("partial_ack", 0),
                "sender_active_fraction": stats.sender_active_samples / max(stats.sample_count, 1),
            })
    return rows


def build_event_rows(flows: Dict[FlowKey, FlowState]) -> List[dict]:
    rows = []
    for flow in flows.values():
        for ev in flow.events:
            rows.append(asdict(ev))
    return rows


def generate_html_report(path: str, flows: Dict[FlowKey, FlowState], meta: dict, cfg: dict) -> None:
    summary_rows = [flow_summary_row(f, cfg) for f in flows.values()]
    class_counts = Counter(r["classification"] for r in summary_rows)
    top_rows = sorted(summary_rows, key=lambda r: (r.get("classification_confidence") or 0, r.get("throughput_bps") or 0), reverse=True)[:50]

    def esc(v):
        return "" if v is None else str(v)

    table_rows = "\n".join(
        "<tr>" + "".join(f"<td>{esc(row.get(col))}</td>" for col in [
            "flow_id", "classification", "classification_confidence", "rtt_handshake_ms", "throughput_bps",
            "wire_pct_of_25g_mean_est", "retransmission_score", "receiver_window_limitation_score",
            "window_full_events", "zero_window_events", "classification_reasons"
        ]) + "</tr>"
        for row in top_rows
    )

    flow_sections = []
    for row in top_rows[:20]:
        flow_sections.append(f"""
        <section class='card'>
          <h3>{esc(row['flow_id'])}</h3>
          <p><strong>Klasse:</strong> {esc(row['classification'])} | <strong>Confidence:</strong> {esc(row['classification_confidence'])}</p>
          <p><strong>RTT Handshake:</strong> {esc(row['rtt_handshake_ms'])} ms | <strong>ACK RTT mean:</strong> {esc(row['ack_rtt_mean_ms'])} ms | <strong>TS RTT mean:</strong> {esc(row['ts_rtt_mean_ms'])} ms</p>
          <p><strong>Throughput:</strong> {esc(row['throughput_bps'])} bps | <strong>25G Wire %:</strong> {esc(row['wire_pct_of_25g_mean_est'])}</p>
          <p><strong>Retrans Score:</strong> {esc(row['retransmission_score'])} | <strong>Receiver-Limitation Score:</strong> {esc(row['receiver_window_limitation_score'])} | <strong>Burstiness:</strong> {esc(row['burstiness_score'])}</p>
          <p><strong>Events:</strong> retrans={esc(row['retransmission_packets'])}, fast_retrans={esc(row['fast_retransmission_packets'])}, dup_ack={esc(row['duplicate_ack_packets'])}, ooo={esc(row['out_of_order_packets'])}, win_full={esc(row['window_full_events'])}, zero_win={esc(row['zero_window_events'])}</p>
          <p><strong>Reasons:</strong> {esc(row['classification_reasons'])}</p>
        </section>
        """)

    html = f"""<!doctype html>
<html lang='de'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>TCP RCA Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background:#f6f6f6; color:#222; }}
h1,h2,h3 {{ margin: 0 0 12px 0; }}
.card {{ background:#fff; border:1px solid #ddd; border-radius:8px; padding:16px; margin:16px 0; }}
table {{ width:100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ border:1px solid #ccc; padding:8px; text-align:left; vertical-align:top; }}
th {{ background:#eee; }}
.grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
.small {{ color:#555; font-size: 14px; }}
</style>
</head>
<body>
<h1>TCP RCA Report</h1>
<div class='card'>
  <p><strong>Flows:</strong> {meta['flow_count']} | <strong>Full RCA:</strong> {meta['full_rca_flows']} | <strong>Reduced:</strong> {meta['reduced_flows']} | <strong>Packets:</strong> {meta['packet_count']}</p>
  <p><strong>Capture position:</strong> near_sender | <strong>Line rate:</strong> {cfg.get('line_rate_bps')} bps | <strong>Windows:</strong> {', '.join(str(w) for w in cfg.get('window_sizes_ms', []))} ms</p>
  <p class='small'>Dieser Report ist ein Arbeitsreport der Baseline-RCA. Kapazitätsschätzung und Thresholds sind konfigurierbar und sollen später über gelabelte Sessions getuned werden.</p>
</div>
<div class='grid'>
  {''.join(f"<div class='card'><h3>{k}</h3><p>{v}</p></div>" for k, v in class_counts.items())}
</div>
<div class='card'>
  <h2>Auffällige Sessions</h2>
  <table>
    <thead>
      <tr>
        <th>Flow</th><th>Class</th><th>Confidence</th><th>RTT handshake ms</th><th>Throughput bps</th><th>25G wire %</th><th>Retrans score</th><th>Recv-lim score</th><th>Window full</th><th>Zero window</th><th>Reasons</th>
      </tr>
    </thead>
    <tbody>{table_rows}</tbody>
  </table>
</div>
<h2>Flow-Details</h2>
{''.join(flow_sections)}
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def write_outputs(outdir: str, flows: Dict[FlowKey, FlowState], meta: dict, cfg: dict) -> None:
    os.makedirs(outdir, exist_ok=True)
    summary_rows = [flow_summary_row(f, cfg) for f in flows.values()]
    interval_100 = build_interval_rows(flows, cfg, 100)
    interval_1000 = build_interval_rows(flows, cfg, 1000)
    event_rows = build_event_rows(flows)

    write_csv(os.path.join(outdir, "flows_summary.csv"), summary_rows)
    write_csv(os.path.join(outdir, "flows_intervals_100ms.csv"), interval_100)
    write_csv(os.path.join(outdir, "flows_intervals_1s.csv"), interval_1000)
    write_csv(os.path.join(outdir, "flows_events.csv"), event_rows)

    write_json(os.path.join(outdir, "flows_summary.json"), summary_rows)
    write_json(os.path.join(outdir, "flows_intervals_100ms.json"), interval_100)
    write_json(os.path.join(outdir, "flows_intervals_1s.json"), interval_1000)
    write_json(os.path.join(outdir, "flows_events.json"), event_rows)
    write_json(os.path.join(outdir, "run_metadata.json"), {"meta": meta, "config": cfg})

    generate_html_report(os.path.join(outdir, "report.html"), flows, meta, cfg)


def export_template_config(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive TCP RCA pipeline for server-near TAP captures")
    parser.add_argument("pcap", nargs="?", help="Input PCAP/PCAPNG file")
    parser.add_argument("--config", help="JSON config file", default=None)
    parser.add_argument("--csv-input", help="Use pre-extracted tshark CSV instead of running tshark", default=None)
    parser.add_argument("--outdir", help="Output directory", default="output/rca_run")
    parser.add_argument("--export-config", help="Write template config JSON and exit", default=None)
    args = parser.parse_args()

    if args.export_config:
        export_template_config(args.export_config)
        return

    if not args.pcap and not args.csv_input:
        parser.error("either pcap or --csv-input is required")

    cfg = load_config(args.config)
    os.makedirs(args.outdir, exist_ok=True)

    csv_input = args.csv_input
    if not csv_input:
        csv_input = os.path.join(args.outdir, "tshark_extract.csv")
        run_tshark(args.pcap, csv_input)

    flows, meta = process_packets(csv_input, cfg)
    write_outputs(args.outdir, flows, meta, cfg)


if __name__ == "__main__":
    main()
