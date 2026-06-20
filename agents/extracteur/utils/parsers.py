"""
parsers.py
Parsing utilities for syslog, NDJSON, and JSON log formats.
Production-ready for live ingestion.
"""

import hashlib
import json
import os
import socket
import re
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

# ============================================================================
# CLEANUP UTILITIES
# ============================================================================

def cleanup_raw_directory(raw_dir: str = "data/raw") -> int:
    """
    Nettoie le dossier data/raw/ en supprimant tous les fichiers de test.
    Supprime les extensions: .log, .json, .ndjson
    Retourne le nombre de fichiers supprimés.
    """
    import glob

    removed_count = 0
    extensions = ["*.log", "*.json", "*.ndjson"]

    if not os.path.exists(raw_dir):
        return 0

    for ext in extensions:
        pattern = os.path.join(raw_dir, ext)
        for filepath in glob.glob(pattern):
            try:
                os.remove(filepath)
                removed_count += 1
            except OSError as e:
                print(f"Warning: Could not remove {filepath}: {e}")

    return removed_count


# ============================================================================
# SYSLOG PARSING
# ============================================================================

def parse_syslog_line(line: str, year: int = 2026) -> Dict[str, Any]:
    """
    Parse a single syslog line into a normalized dictionary.
    Handles RFC 3164 and dynamic variations gracefully.
    """
    cleaned = line.strip().replace("\r", "").replace("\n", "")

    result = {
        "raw": cleaned,
        "timestamp": None,
        "host": None,
        "process": None,
        "priority": None,
        "message": None,
        "parse_error": None,
    }

    try:
        # Strip <PRI> prefix if present: <34>
        pri_match = re.match(r'^<(\d+)>', cleaned)
        if pri_match:
            result["priority"] = int(pri_match.group(1))
            cleaned = cleaned[pri_match.end():]

        # Regex flexible pour matcher les dates avec ou sans année (ex: Jun 17 2026 ... ou Jun 17 15:25:00)
        pattern = re.compile(
            r'^(\w{3}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2})'  # timestamp
            r'\s+(\S+)'                                              # host
            r'\s+([^:]+):\s*'                                        # process
            r'(.*)$'                                                 # message
        )
        m = pattern.match(cleaned)
        if m:
            result["timestamp"] = m.group(1).strip()
            result["host"] = m.group(2)
            result["process"] = m.group(3).strip()
            result["message"] = m.group(4).strip()
        else:
            # Fallback robuste s'il y a un délimiteur par deux-points
            if ":" in cleaned:
                parts = cleaned.split(":", 1)
                result["message"] = parts[1].strip()
                # Tenter d'extraire le process du côté gauche du colon
                left_side = parts[0].strip().split()
                if left_side:
                    result["process"] = left_side[-1]
            else:
                result["message"] = cleaned
            result["parse_error"] = "Used fallback parser"

    except Exception as e:
        result["parse_error"] = str(e)
        result["message"] = cleaned

    return result


# ============================================================================
# LIVE SYSLOG SOCKET LISTENER
# ============================================================================

def create_syslog_socket(host: str = "0.0.0.0", port: int = 1514,
                         use_tcp: bool = False, timeout: float = 1.0) -> socket.socket:
    """
    Crée un socket UDP/TCP pour écouter les logs syslog en temps réel.
    Port par défaut: 1514 (non-privilégié, évite sudo)
    """
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_STREAM if use_tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.bind((host, port))
    return sock


def stream_syslog_messages(sock: socket.socket) -> Iterator[str]:
    """
    Générateur qui yield les messages syslog reçus via le socket.
    Mode non bloquant avec timeout, pour boucle infinie daemon.
    """
    try:
        while True:
            try:
                if sock.type == socket.SOCK_DGRAM:
                    data, _ = sock.recvfrom(65535)
                else:
                    data = sock.recv(65535)
                yield data.decode("utf-8", errors="replace")
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
    except GeneratorExit:
        sock.close()


# ============================================================================
# NETWORK TRAFFIC PARSING (TSHARK - EK FORMAT)
# ============================================================================

_EK_DEBUG_LOGGED: bool = False


def _ek_get_nested(layers: Dict[str, Any], layer_name: str, *keys: str) -> Optional[str]:
    """
    Cherche une clé de manière récursive ou directe dans l'objet de la couche.
    Prend en compte les dictionnaires imbriqués remontés par tshark -T ek.
    Sécurise l'extraction si la valeur finale est encapsulée dans une liste.
    """
    # 1. Aller chercher la sous-couche (ex: layers.get("ip"))
    target_layer = layers.get(layer_name)
    
    # Si la sous-couche n'existe pas, on cherche à la racine de layers au cas où c'est flatté
    search_dict = target_layer if isinstance(target_layer, dict) else layers

    for key in keys:
        val = search_dict.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            val = val[0] if val else None
        if val is not None:
            s = str(val).strip()
            if s:
                return s
    return None


def parse_tshark_json(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from tshark -T ek (Elasticsearch/NDJSON) output.
    Supports both nested layer structures and flat key mappings.
    """
    global _EK_DEBUG_LOGGED

    if not line or not line.strip():
        return None

    try:
        packet = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    if not isinstance(packet, dict):
        return None

    # Skip tshark index/metadata lines
    if "index" in packet and isinstance(packet.get("index"), dict):
        return None

    try:
        layers = packet.get("layers")

        if not _EK_DEBUG_LOGGED and isinstance(layers, dict) and layers:
            _EK_DEBUG_LOGGED = True
            sample_keys = list(layers.keys())[:40]
            print(f"[🔬 EK DEBUG] First packet layer keys: {sample_keys}")

        if not isinstance(layers, dict) or not layers:
            return None

        # ── Source & Destination IP (Extraction récursive sécurisée) ──────────
        # Tente l'extraction de la couche IPv4 'ip' puis IPv6 'ipv6'
        src_ip = _ek_get_nested(layers, "ip", "ip_ip_src", "ip_src", "src") or \
                 _ek_get_nested(layers, "ipv6", "ipv6_ipv6_src", "ipv6_src", "src")

        dst_ip = _ek_get_nested(layers, "ip", "ip_ip_dst", "ip_dst", "dst") or \
                 _ek_get_nested(layers, "ipv6", "ipv6_ipv6_dst", "ipv6_dst", "dst")

        # ── Protocol ─────────────────────────────────────────────────────────
        # On vérifie d'abord les signatures directes des clés présentes
        if "udp" in layers:
            protocol = "UDP"
        elif "tcp" in layers:
            protocol = "TCP"
        elif "icmp" in layers:
            protocol = "ICMP"
        elif "icmpv6" in layers:
            protocol = "ICMPv6"
        else:
            raw_proto = _ek_get_nested(layers, "frame", "frame_frame_protocols", "frame_protocols", "protocols")
            protocol = _map_protocol(raw_proto)

        # ── Timestamp ────────────────────────────────────────────────────────
        ts_epoch = _ek_get_nested(layers, "frame", "frame_frame_time_epoch", "frame_time_epoch", "time_epoch")
        timestamp = _parse_timestamp(ts_epoch, packet.get("timestamp"))

        # ── Packet length ─────────────────────────────────────────────────────
        length = 0
        len_raw = _ek_get_nested(layers, "frame", "frame_frame_len", "frame_len", "len")
        if len_raw:
            try:
                length = int(float(len_raw))
            except (ValueError, TypeError):
                pass

        return {
            "timestamp": timestamp,
            "source": "network",
            "src_ip": src_ip or "unknown",
            "dst_ip": dst_ip or "unknown",
            "protocol": protocol,
            "length": length,
            "raw_packet": packet,
        }

    except Exception as e:
        print(f"[❌ ERROR] parse_tshark_json: {e}")
        return None


def _map_protocol(raw_proto: Optional[str]) -> str:
    """
    Map a tshark frame.protocols stack string to a clean uppercase label.
    """
    if not raw_proto:
        return "UNKNOWN"

    p = raw_proto.lower()

    if "icmpv6" in p:
        return "ICMPv6"
    if "icmp" in p:
        return "ICMP"
    if "tcp" in p:
        return "TCP"
    if "udp" in p:
        return "UDP"
    if "arp" in p:
        return "ARP"
    if "dns" in p:
        return "DNS"
    if "tls" in p or "ssl" in p:
        return "TLS"
    if "http" in p:
        return "HTTP"
    if "dhcp" in p or "bootp" in p:
        return "DHCP"

    segments = [s.strip() for s in raw_proto.split(":") if s.strip()]
    return segments[-1].upper() if segments else raw_proto.upper()


def _parse_timestamp(epoch_str: Optional[str], ts_fallback: Optional[str]) -> str:
    """
    Convert an epoch float string to ISO-8601.
    """
    if epoch_str:
        try:
            return datetime.fromtimestamp(float(epoch_str)).isoformat()
        except (ValueError, TypeError, OSError):
            pass

    if ts_fallback:
        return str(ts_fallback)

    return datetime.now().isoformat()


# ============================================================================
# JSON/NDJSON LOADING
# ============================================================================

def load_json_records(path: str, is_ndjson: bool = False) -> List[Dict[str, Any]]:
    """
    Load records from a JSON or NDJSON file.
    """
    records = []

    if not os.path.exists(path):
        print(f"[⚠️ WARNING] File not found: {path}")
        return records

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except IOError as e:
        print(f"[❌ ERROR] Cannot read file {path}: {e}")
        return records

    if is_ndjson:
        for i, line in enumerate(content.strip().split("\n"), 1):
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[⚠️ WARNING] Skipping malformed NDJSON line {i} in {path}: {e}")
    else:
        try:
            parsed = json.loads(content)
            records = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError as e:
            print(f"[❌ ERROR] Invalid JSON in {path}: {e}")

    return records


# ============================================================================
# SEVERITY NORMALIZATION
# ============================================================================

def normalize_severity(severity: Any) -> float:
    """
    Normalize severity to a 0-1 score.
    """
    if isinstance(severity, float):
        return max(0.0, min(1.0, severity))

    if isinstance(severity, int):
        return max(0.0, min(1.0, severity / 10.0))

    severity_map = {
        "debug":     0.1,
        "info":      0.2,
        "low":       0.3,
        "medium":    0.5,
        "high":      0.7,
        "critical":  0.9,
        "emergency": 1.0,
    }

    if isinstance(severity, str):
        mapped = severity_map.get(severity.lower())
        if mapped is not None:
            return mapped
        lower = severity.lower()
        for kw, score in sorted(severity_map.items(), key=lambda x: -x[1]):
            if kw in lower:
                return score
        return 0.5

    return 0.5


# ============================================================================
# DETERMINISTIC ID GENERATION
# ============================================================================

def generate_deterministic_id(timestamp: str, source: str, message: str) -> str:
    """
    Generate deterministic event ID using SHA-256.
    Zero-LLM: Pure deterministic computation.
    """
    content = f"{timestamp}:{source}:{message}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]