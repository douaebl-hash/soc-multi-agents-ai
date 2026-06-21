"""
extractor.py
Multi-Source Ingestion Agent (Network Traffic, Syslog UDP & SIEM JSON).
Fully compliant with the SOC Multi-Agent Architecture.
"""

import json
import os
import subprocess
import threading
import time
import sys
import queue
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# On récupère le dossier où se trouve extractor.py (agents/extracteur)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# On remonte de deux niveaux pour atteindre la racine globale (SOC-MULTI-AGENTS-AI)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

# Configuration des paths Python pour les imports
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if CURRENT_DIR not in sys.path:
    sys.path.insert(1, CURRENT_DIR)

from shared_memory import SharedMemory
from utils.parsers import (
    parse_tshark_json,
    parse_syslog_line,
    generate_deterministic_id,
    normalize_severity,
)

# Configuration absolue des dossiers de données
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

# ============================================================================
# UTILS & VALIDATION CHECKS
# ============================================================================

def is_tshark_available() -> bool:
    """Vérifie de manière sécurisée si tshark est disponible sur le système."""
    try:
        # Exécute une commande légère pour tester l'exécutable
        subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False

# ============================================================================
# EVENT STRUCTURE
# ============================================================================

@dataclass
class Event:
    """Normalized security event structure."""
    timestamp: str
    source: str
    severity: float
    message: str
    event_id: str = field(default="")
    raw: str = field(default="")

    def __post_init__(self):
        if not self.event_id:
            self.event_id = self._generate_id()

    def _generate_id(self) -> str:
        return generate_deterministic_id(self.timestamp, self.source, self.message)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "message": self.message,
            "raw": self.raw,
        }


# ============================================================================
# STATUS TRACKING
# ============================================================================

@dataclass
class CaptureStatus:
    packets_captured: int = 0
    logs_captured: int = 0
    siem_alerts_captured: int = 0
    errors: List[str] = field(default_factory=list)
    active: bool = False
    current_interface: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_captured": self.packets_captured,
            "logs_captured": self.logs_captured,
            "siem_alerts_captured": self.siem_alerts_captured,
            "errors": self.errors,
            "active": self.active,
            "current_interface": self.current_interface,
        }


# ============================================================================
# INTERFACE DETECTION (TSHARK)
# ============================================================================

def detect_active_interface() -> Optional[str]:
    if sys.platform == "win32":
        try:
            cmd = ["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        return "Wi-Fi"
        
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "dev" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "dev" and i + 1 < len(parts):
                            return parts[i + 1]
    except Exception:
        pass
    return "eth0"


# ============================================================================
# MULTI-SOURCE EXTRACTOR AGENT
# ============================================================================

class NetworkCaptureAgent:
    """Multi-source ingestion agent (tshark live capture, Syslog UDP & SIEM JSON files)."""

    def __init__(self, network_interface: Optional[str] = None, network_filter: Optional[str] = None, syslog_port: int = 1514):
        self.memory = SharedMemory(base_dir=PROCESSED_DIR)
        self.status = CaptureStatus()
        self.network_interface = network_interface
        self.network_filter = network_filter
        self.syslog_port = syslog_port
        self.running = False
        self.shutdown_event = threading.Event()
        
        # File d'attente unique centralisant toutes les sources du schéma
        self._global_queue: queue.Queue = queue.Queue()
        self._tshark_thread: Optional[threading.Thread] = None
        self._syslog_thread: Optional[threading.Thread] = None
        self._siem_thread: Optional[threading.Thread] = None

    def _tshark_reader(self) -> None:
        """Source 1 : Capture Réseau en direct via Tshark."""
        # --- AJOUT DE LA SÉCURITÉ DE VÉRIFICATION ---
        if not is_tshark_available():
            print("[🟡 NETWORK CAPTURE INDISPONIBLE] Tshark ou le pilote Npcap/Wireshark est introuvable sur cette machine.")
            self.status.errors.append("tshark executable or packet capture driver missing")
            return

        iface = self.network_interface or detect_active_interface()
        if not iface:
            self.status.errors.append("No active network interface found")
            return

        self.status.current_interface = iface
        cmd = ["tshark", "-i", any, "-T", "ek", "-l"]
        if self.network_filter:
            cmd.extend(["-f", self.network_filter])

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, text=True)
            self.status.active = True
            print(f"[✅ NETWORK] Capturing on interface: {iface}")
        except Exception as e:
            self.status.errors.append(f"tshark error: {e}")
            return

        try:
            for line in proc.stdout:
                if not self.running or self.shutdown_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if "index" in data:
                        continue
                    parsed = parse_tshark_json(json.dumps(data))
                    if parsed:
                        self._global_queue.put(("PACKET", parsed))
                except json.JSONDecodeError:
                    continue
        finally:
            if proc.poll() is None:
                proc.terminate()
            print("[🔴 NETWORK] Capture thread stopped")

    def _syslog_reader(self) -> None:
        """Source 2 : Écouteur de Logs Systèmes (Syslog UDP)."""
        HOST = "127.0.0.1"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((HOST, self.syslog_port))
            sock.settimeout(1.0)
            print(f"[✅ SYSLOG] Listening on UDP {HOST}:{self.syslog_port}")
        except Exception as e:
            self.status.errors.append(f"Syslog socket bind error: {e}")
            sock.close()
            return

        while self.running and not self.shutdown_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                line = data.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue
                parsed = parse_syslog_line(line)
                if parsed:
                    self._global_queue.put(("SYSLOG", parsed))
            except socket.timeout:
                continue
            except Exception as e:
                self.status.errors.append(str(e))
                break
        sock.close()
        print("[🔴 SYSLOG] Receiver thread stopped")

    def _siem_reader(self) -> None:
        """Source 3 : Ingestion en flux (Streaming) des alertes de sécurité (SIEM).
        Ouvre le fichier une seule fois et lit uniquement les nouvelles lignes."""
        siem_file_path = os.path.join(RAW_DIR, "siem_alerts.jsonl")
        print(f"[🔍 SIEM WATCH] Initializing stream reader for: {siem_file_path}")
        
        # Attente passive si le fichier n'existe pas encore au démarrage de la chaîne
        while self.running and not self.shutdown_event.is_set() and not os.path.exists(siem_file_path):
            time.sleep(1.0)
            
        if not self.running or self.shutdown_event.is_set():
            return

        print("[🟢 SIEM STREAM] JSON Source file locked. Starting single-open stream process...")
        
        try:
            with open(siem_file_path, "r", encoding="utf-8") as f:
                while self.running and not self.shutdown_event.is_set():
                    line = f.readline()
                    
                    # S'il n'y a pas de nouvelle ligne écrite, on dort 1 seconde (évite l'attente active CPU)
                    if not line:
                        time.sleep(1.0)
                        continue
                        
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Traitement de l'alerte SIEM reçue en temps réel (Ligne JSON unique)
                    try:
                        alert_data = json.loads(line)
                        self._global_queue.put(("SIEM", alert_data))
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            self.status.errors.append(f"SIEM stream reader crash: {e}")
            
        print("[🔴 SIEM] Reader thread stopped")

    def _process_global_queue(self) -> None:
        """Dépile, normalise et filtre l'ensemble des flux convergés."""
        processed = 0
        while processed < 100 and not self._global_queue.empty() and self.running:
            try:
                source_type, data_payload = self._global_queue.get_nowait()

                # --- 1. PARSING FLUX RÉSEAU ---
                if source_type == "PACKET":
                    timestamp = data_payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
                    proto = data_payload.get("protocol", "unknown").upper()
                    src_ip = data_payload.get("src_ip", "unknown")
                    dst_ip = data_payload.get("dst_ip", "unknown")
                    dst_port = data_payload.get("dst_port", "")
                    
                    message = f"Network Traffic observed: {proto} {src_ip} -> {dst_ip}"
                    if dst_port: message += f":{dst_port}"
                    
                    severity_score = 0.4
                    if dst_port in [22, 445, 3389]:
                        severity_score = 0.7
                        message += " | Sensitive Port access attempt"

                    event = Event(
                        timestamp=timestamp, source="network", severity=severity_score,
                        message=message, raw=json.dumps(data_payload)
                    )
                    self.status.packets_captured += 1

                # --- 2. PARSING FLUX SYSLOG ---
                elif source_type == "SYSLOG":
                    timestamp = datetime.now(timezone.utc).isoformat()
                    host = data_payload.get("host", "unknown")
                    process = data_payload.get("process", "unknown")
                    syslog_msg = data_payload.get("message", "")
                    
                    message = f"[{process}@{host}] {syslog_msg}"
                    priority = data_payload.get("priority")
                    severity_score = normalize_severity(priority if priority is not None else syslog_msg)

                    event = Event(
                        timestamp=timestamp, source="syslog", severity=severity_score,
                        message=message, raw=json.dumps(data_payload)
                    )
                    self.status.logs_captured += 1

                # --- 3. PARSING FLUX SIEM ---
                elif source_type == "SIEM":
                    timestamp = data_payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
                    rule_name = data_payload.get("rule_name", "Generic SIEM Alert")
                    description = data_payload.get("description", "No description provided")
                    
                    message = f"[SIEM ALERT] {rule_name} - {description}"
                    raw_severity = data_payload.get("severity", "medium")
                    severity_score = normalize_severity(raw_severity)

                    event = Event(
                        timestamp=timestamp, source="siem", severity=severity_score,
                        message=message, raw=json.dumps(data_payload)
                    )
                    self.status.siem_alerts_captured += 1
                else:
                    continue

                # --- FILTRAGE ET PERSISTANCE (MÉMOIRE PARTAGÉE) ---
                self.publish(event, "events_structured")
                
                if self.detect_relevant(event):
                    self.publish(event, "pending_analysis")

                print(f"[🟢 EVENT EXTRACTED] {event.event_id[:8]} | Source: {event.source.upper()} | Criticality: {event.severity:.2f} | {event.message[:65]}")
                processed += 1
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"[❌ ERROR] Queue pipeline error: {e}")
                break

    def detect_relevant(self, event: Event) -> bool:
        keywords = ["attaque", "critical", "erreur", "echec", "brute", "intrusion", "attack", "failed", "unauthorized", "denied"]
        return any(kw in event.message.lower() for kw in keywords) or event.severity >= 0.7

    def publish(self, event: Event, channel: str) -> None:
        try:
            self.memory.append(channel, event.to_json_dict())
        except Exception as e:
            print(f"[❌ ERROR] SharedMemory write failure on {channel}: {e}")

    def run_daemon(self, poll_interval: float = 0.1) -> None:
        """Démarre la collecte simultanée pour les 3 canaux de l'architecture."""
        self.running = True
        self.shutdown_event.clear()
        
        # Lancement asynchrone des 3 capteurs du schéma
        self._tshark_thread = threading.Thread(target=self._tshark_reader, daemon=True)
        self._syslog_thread = threading.Thread(target=self._syslog_reader, daemon=True)
        self._siem_thread = threading.Thread(target=self._siem_reader, daemon=True)
        
        self._tshark_thread.start()
        self._syslog_thread.start()
        self._siem_thread.start()

        time.sleep(0.5)
        print("\n[✅ SOC AGENT] Central Multi-Source Engine fully operational.")
        
        # --- MODIFICATION DYNAMIQUE DE L'AFFICHAGE DE STATUT ---
        net_status = "🟢 Networks Capture (tshark)" if is_tshark_available() else "❌ Networks Capture (tshark MISSING/DRIVER ERROR)"
        print(f"Listening to: {net_status} | 🟢 Syslog Streams (UDP) | 🟢 SIEM Feeds (JSON)")

        try:
            while self.running and not self.shutdown_event.is_set():
                self._process_global_queue()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("\n[⚠️] Stopping core engine threads...")
        finally:
            self.running = False
            self.shutdown_event.set()
            if self._tshark_thread: self._tshark_thread.join(timeout=1)
            if self._syslog_thread: self._syslog_thread.join(timeout=1)
            if self._siem_thread: self._siem_thread.join(timeout=1)
            print("[🔴 DAEMON] Multi-Source Agent cleanly terminated.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SOC Extractor Agent Core Engine")
    parser.add_argument("--daemon", action="store_true", help="Run continuous multi-source engine")
    args = parser.parse_args()

    agent = NetworkCaptureAgent()
    if args.daemon:
        agent.run_daemon()
    else:
        print("[!] Please use '--daemon' to run the multi-source collection engine.")