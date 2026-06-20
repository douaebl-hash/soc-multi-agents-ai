"""
extractor.py
Live Network Traffic Capture Agent using tshark/Wireshark.
Captures real-time packets from NIC and writes structured JSON events.
"""

import json
import os
import subprocess
import threading
import time
import sys
import queue
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# On récupère le dossier où se trouve extractor.py (agents/extracteur)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# On remonte de deux niveaux pour atteindre la racine globale (SOC-MULTI-AGENTS-AI)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

# On ajoute dynamiquement la racine et le dossier courant au path Python pour corriger les imports
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if CURRENT_DIR not in sys.path:
    sys.path.insert(1, CURRENT_DIR)

# Maintenant, les imports fonctionneront peu importe d'où tu lances le script
from shared_memory import SharedMemory
from utils.parsers import (
    parse_tshark_json,
    generate_deterministic_id,
    normalize_severity,
)

# Configuration absolue des dossiers de données à la racine du projet
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

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
    errors: List[str] = field(default_factory=list)
    active: bool = False
    current_interface: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_captured": self.packets_captured,
            "errors": self.errors,
            "active": self.active,
            "current_interface": self.current_interface,
        }


# ============================================================================
# LIVE NETWORK CAPTURE
# ============================================================================

def detect_active_interface() -> Optional[str]:
    print("[🔍] Probing for active network interface...")
    
    # Compatibilité Windows (PowerShell Get-NetAdapter)
    if sys.platform == "win32":
        try:
            cmd = ["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                iface = result.stdout.strip()
                print(f"[✅ Windows] Found active interface: {iface}")
                return iface
        except Exception:
            pass
        return "Wi-Fi" # Valeur par défaut standard sous Windows si le probing échoue
        
    # Compatibilité Linux / Mac
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "dev" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "dev" and i + 1 < len(parts):
                            iface = parts[i + 1]
                            print(f"[✅ Linux] Found active interface: {iface}")
                            return iface
    except Exception as e:
        print(f"[❌] Interface detection failed: {e}")

    for iface in ["eth0", "wlan0", "enp0s3", "ens33", "en0", "lo"]:
        try:
            subprocess.run(["ip", "link", "show", iface], capture_output=True, timeout=1)
            print(f"[✅] Found interface: {iface}")
            return iface
        except Exception:
            continue

    print("[⚠️] No active interface found")
    return None


class NetworkCaptureAgent:
    """Live tshark capture and JSON event writer."""

    def __init__(self, network_interface: Optional[str] = None, network_filter: Optional[str] = None):
        self.memory = SharedMemory(base_dir=PROCESSED_DIR)
        self.status = CaptureStatus()
        self.network_interface = network_interface
        self.network_filter = network_filter
        self.running = False
        self.shutdown_event = threading.Event()
        self._tshark_queue: queue.Queue = queue.Queue()
        self._tshark_thread: Optional[threading.Thread] = None

    def _tshark_reader(self) -> None:
        iface = self.network_interface or detect_active_interface()
        if not iface:
            self.status.errors.append("No active network interface found")
            self.status.active = False
            return

        self.status.current_interface = iface
        cmd = ["tshark", "-i", iface, "-T", "ek", "-l"]
        if self.network_filter:
            cmd.extend(["-f", self.network_filter])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True,
            )
            self.status.active = True
            print(f"[✅ NETWORK] Capturing on {iface} (PID: {proc.pid})")
        except FileNotFoundError:
            self.status.errors.append("tshark binary not found")
            self.status.active = False
            print("[❌ ERROR] tshark not found - install wireshark-cli")
            return
        except Exception as e:
            self.status.errors.append(str(e))
            self.status.active = False
            print(f"[❌ ERROR] {e}")
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
                        self._tshark_queue.put(("PACKET", parsed))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"[❌ ERROR] Network capture thread: {e}")
            self.status.errors.append(str(e))
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            print("[🔴 NETWORK] Capture stopped")

    def _process_network_queue(self) -> None:
        processed = 0
        while processed < 200 and not self._tshark_queue.empty() and self.running:
            try:
                item_type, packet = self._tshark_queue.get_nowait()
                if item_type != "PACKET":
                    continue

                timestamp = packet.get("timestamp") or datetime.now(timezone.utc).isoformat()
                
                proto = packet.get("protocol", "unknown").upper()
                src_ip = packet.get("src_ip", "unknown")
                dst_ip = packet.get("dst_ip", "unknown")
                dst_port = packet.get("dst_port", "")
                
                port_suffix = f":{dst_port}" if dst_port else ""
                message = f"Network Traffic observed: {proto} {src_ip} -> {dst_ip}{port_suffix}"
                
                severity_score = 0.5
                if dst_port in [22, 3389, 445, 80, 443]:
                    if dst_port == 22:
                        message += " | Potential SSH connection attempt"
                    elif dst_port == 445:
                        message += " | SMB Traffic - Checking for potential lateral movement"
                        severity_score = 0.75

                event = Event(
                    timestamp=timestamp,
                    source="network",
                    severity=severity_score,
                    message=message,
                    raw=json.dumps(packet.get("raw_packet", packet)),
                )

                self.publish(event, "events_structured")
                
                if self.detect_relevant(event):
                    self.publish(event, "pending_analysis")

                self.status.packets_captured += 1
                print(f"[🟢 EVENT EXTRACTED] {event.event_id[:8]} | {message[:75]}")
                processed += 1
            except queue.Empty:
                break
            except Exception as e:
                print(f"[❌ ERROR] Queue processing: {e}")
                break

    def detect_relevant(self, event: Event) -> bool:
        keywords = [
            "attaque", "critical", "erreur", "echec", "brute", "force", "intrusion",
            "attack", "error", "failure", "failed", "password", "invalid user",
            "ddos", "unauthorized", "denied", "smb", "ssh", "movement",
        ]
        return any(kw in event.message.lower() for kw in keywords) or event.severity >= 0.7

    def publish(self, event: Event, channel: str = "events_structured") -> None:
        try:
            self.memory.append(channel, event.to_json_dict())
        except Exception as e:
            print(f"[❌ ERROR] Publish {channel}: {e}")

    def get_status(self) -> Dict[str, Any]:
        return self.status.to_dict()

    def run(self) -> Dict[str, Any]:
        """Run a single-shot network session."""
        self.running = True
        self._tshark_thread = threading.Thread(target=self._tshark_reader, daemon=True)
        self._tshark_thread.start()

        try:
            while self.running and not self.shutdown_event.is_set():
                self._process_network_queue()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("[⚠️] Interrupted")
        finally:
            self.running = False
            self.shutdown_event.set()
            if self._tshark_thread:
                self._tshark_thread.join(timeout=2)

        return self.status.to_dict()

    def run_daemon(self, poll_interval: float = 0.1) -> None:
        """Continuous capture loop."""
        # FIX ICI : self.running doit être activé AVANT de démarrer le thread lecteur
        self.running = True
        self.shutdown_event.clear()
        
        self._tshark_thread = threading.Thread(target=self._tshark_reader, daemon=True)
        self._tshark_thread.start()

        time.sleep(0.5)

        print("[✅ DAEMON] Live network capture running. Press Ctrl+C to stop.\n")
        print(f"[📊] Interface: {self.status.current_interface or 'pending'}")

        try:
            while self.running and not self.shutdown_event.is_set():
                self._process_network_queue()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("\n[⚠️] Shutting down...")
        finally:
            self.running = False
            self.shutdown_event.set()
            if self._tshark_thread:
                self._tshark_thread.join(timeout=2)
            print("[🔴 DAEMON] Stopped.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extracteur - Live Network Capture")
    parser.add_argument("--daemon", action="store_true", help="Run continuous capture")
    parser.add_argument("--network-interface", help="Interface to capture (e.g., eth0, wlan0)")
    parser.add_argument("--network-filter", help="BPF filter for tshark (e.g., 'tcp port 22')")
    args = parser.parse_args()

    agent = NetworkCaptureAgent(
        network_interface=args.network_interface,
        network_filter=args.network_filter,
    )

    if args.daemon:
        agent.run_daemon()
    else:
        result = agent.run()
        print(json.dumps(result, indent=2))