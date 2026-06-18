"""
extractor.py
SecurityAgent - Production-ready for log ingestion and traffic monitoring.
Bulletproof: No silent failures, async-safe, graceful shutdown.
"""

import hashlib
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterator, List, Optional

from src.utils.shared_memory import SharedMemory
from src.utils.parsers import (
    cleanup_raw_directory,
    parse_syslog_line,
    parse_tshark_json,
    generate_deterministic_id,
    normalize_severity,
)

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
        """Generate deterministic event ID from content (Zero-LLM)."""
        return generate_deterministic_id(self.timestamp, self.source, self.message)

    def to_json_dict(self) -> Dict[str, Any]:
        """Convertit l'événement en dictionnaire propre pour l'Agent Analyseur."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "message": self.message,
            "raw": self.raw
        }


# ============================================================================
# STATUS TRACKING
# ============================================================================

@dataclass
class ModuleStatus:
    """Track health status of ingestion modules."""
    syslog_active: bool = False
    syslog_error: Optional[str] = None
    network_active: bool = False
    network_error: Optional[str] = None
    events_processed: int = 0
    events_relevant: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "syslog_active": self.syslog_active,
            "syslog_error": self.syslog_error,
            "network_active": self.network_active,
            "network_error": self.network_error,
            "events_processed": self.events_processed,
            "events_relevant": self.events_relevant,
        }


# ============================================================================
# LIVE INGESTION - NETWORK INTERFACE DETECTION
# ============================================================================

def detect_active_interface() -> Optional[str]:
    """Detect the active network interface (eth0, wlan0, etc.)."""
    print("[🔍 DETECT] Probing for active network interface...")
    
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "dev" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "dev" and i + 1 < len(parts):
                            iface = parts[i + 1]
                            print(f"[✅ DETECT] Found active interface: {iface}")
                            return iface
    except subprocess.TimeoutExpired:
        print("[❌ ERROR] Timeout detecting network interface")
        return None
    except FileNotFoundError:
        print("[❌ ERROR] 'ip' command not found - install iproute2 package")
        return None
    except Exception as e:
        print(f"[❌ ERROR] Unexpected error detecting interface: {e}")
        return None

    for iface in ["eth0", "wlan0", "en0", "enp0s3", "ens33"]:
        try:
            subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True,
                timeout=1,
                check=True
            )
            print(f"[✅ DETECT] Found interface: {iface}")
            return iface
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            print("[❌ ERROR] 'ip' command not found - install iproute2 package")
            return None
        except subprocess.CalledProcessError:
            continue
        except Exception as e:
            print(f"[❌ ERROR] Unexpected error checking interface {iface}: {e}")
            continue

    print("[⚠️ WARNING] No active network interface found - network capture disabled")
    return None


# ============================================================================
# SECURITY AGENT - MAIN CLASS
# ============================================================================

class SecurityAgent:
    """Production-ready security agent for log ingestion and traffic monitoring."""

    def __init__(self,
                 syslog_port: int = 1514,
                 syslog_tcp: bool = False,
                 network_interface: Optional[str] = None,
                 network_filter: Optional[str] = None,
                 raw_dir: str = "data/raw"):
        self.memory = SharedMemory()
        self.raw_dir = raw_dir
        self.running = False
        self.shutdown_event = threading.Event()
        self.status = ModuleStatus()

        self.syslog_port = syslog_port
        self.syslog_tcp = syslog_tcp
        self.syslog_socket: Optional[socket.socket] = None
        self._syslog_queue: Optional[queue.Queue] = queue.Queue()
        self._tshark_queue: Optional[queue.Queue] = queue.Queue()
        self._tshark_thread: Optional[threading.Thread] = None

        self.network_interface = network_interface
        self.network_filter = network_filter

    def cleanup(self) -> int:
        """Clean old test files in data/raw/."""
        return cleanup_raw_directory(self.raw_dir)

    def _syslog_receiver_thread(self) -> None:
        """Background thread for UDP/TCP syslog reception."""
        try:
            sock_type = socket.SOCK_STREAM if self.syslog_tcp else socket.SOCK_DGRAM
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("0.0.0.0", self.syslog_port))
            self.syslog_socket = sock
            self.status.syslog_active = True
            print(f"[🔵 SYSLOG] Listening on {'TCP' if self.syslog_tcp else 'UDP'} 0.0.0.0:{self.syslog_port}")
        except PermissionError as e:
            self.status.syslog_error = f"Permission denied: {e}"
            self.status.syslog_active = False
            print(f"[❌ ERROR] Syslog port {self.syslog_port} requires elevated privileges: {e}")
            return
        except OSError as e:
            self.status.syslog_error = str(e)
            self.status.syslog_active = False
            print(f"[❌ ERROR] Failed to bind syslog port {self.syslog_port}: {e}")
            return
        except Exception as e:
            self.status.syslog_error = str(e)
            self.status.syslog_active = False
            print(f"[❌ ERROR] Unexpected error initializing syslog: {e}")
            return

        if self.syslog_tcp:
            try:
                sock.listen(5)
                print("[🔵 SYSLOG] TCP listening for connections...")
            except Exception as e:
                print(f"[❌ ERROR] Failed to listen on TCP socket: {e}")

        while self.running and not self.shutdown_event.is_set():
            try:
                if self.syslog_tcp:
                    try:
                        conn, addr = sock.accept()
                        conn.settimeout(1.0)
                        data = conn.recv(65535)
                        conn.close()
                        if data:
                            self._syslog_queue.put(data.decode("utf-8", errors="replace"))
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                else:
                    try:
                        data, addr = sock.recvfrom(65535)
                        self._syslog_queue.put(data.decode("utf-8", errors="replace"))
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            except Exception as e:
                print(f"[❌ ERROR] Unexpected syslog error: {e}")
                continue

        sock.close()
        print("[🔵 SYSLOG] Socket closed.")

    def _network_capture_thread(self) -> None:
        """Background thread for tshark network capture utilizing line-by-line NDJSON streaming."""
        iface = self.network_interface or detect_active_interface()
        if not iface:
            self.status.network_error = "No active network interface found"
            self.status.network_active = False
            print("[❌ ERROR] Network capture disabled: no interface available")
            return

        # -T ek forces single-line JSON format for clean streaming without arrays brackets
        cmd = ["tshark", "-i", iface, "-T", "ek", "-l"]
        if self.network_filter:
            cmd.extend(["-f", self.network_filter])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1, # Line buffered
                text=True
            )
            self.status.network_active = True
            print(f"[✅ NETWORK] Capturing on interface: {iface} (PID: {proc.pid})")
        except FileNotFoundError:
            self.status.network_error = "tshark binary not found"
            self.status.network_active = False
            print("[❌ ERROR] tshark binary not found - install wireshark-cli package")
            return
        except Exception as e:
            self.status.network_error = str(e)
            self.status.network_active = False
            print(f"[❌ ERROR] Failed to start tshark: {e}")
            return

        try:
            # High-performance line streaming architecture
            for line in proc.stdout:
                if not self.running or self.shutdown_event.is_set():
                    break
                
                clean_line = line.strip()
                if not clean_line:
                    continue
                
                try:
                    data = json.loads(clean_line)
                    if "index" in data: # Skip tshark metadata index headers
                        continue
                        
                    parsed = parse_tshark_json(json.dumps(data))
                    if parsed:
                        self._tshark_queue.put(("PACKET", parsed))
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            print(f"[❌ ERROR] Network capture thread exception: {e}")
            self.status.network_error = str(e)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            print("[🔵 NETWORK] Capture thread stopped")

    def _setup_signal_handlers(self) -> None:
        """Setup graceful shutdown handlers."""
        def signal_handler(signum, frame):
            print(f"\n[⚠️ DAEMON] Signal {signum} received - initiating graceful shutdown...")
            self.running = False
            self.shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def run_daemon(self, poll_interval: float = 0.1) -> None:
        """Run in daemon mode: continuous real-time ingestion loop."""
        self.running = True
        self._setup_signal_handlers()

        syslog_thread = threading.Thread(
            target=self._syslog_receiver_thread,
            daemon=True,
            name="syslog-receiver"
        )
        syslog_thread.start()

        if self.network_interface is not None or os.path.exists("/proc/net/dev"):
            network_thread = threading.Thread(
                target=self._network_capture_thread,
                daemon=True,
                name="network-capture"
            )
            network_thread.start()

        time.sleep(0.5)

        print("[✅ DAEMON] Running. Press Ctrl+C to stop.\n")
        print(f"[📊 STATUS] Syslog: {'ACTIVE' if self.status.syslog_active else 'INACTIVE'} | "
              f"Network: {'ACTIVE' if self.status.network_active else 'INACTIVE'}")

        while self.running and not self.shutdown_event.is_set():
            self._process_syslog_queue()
            self._process_network_queue()
            time.sleep(poll_interval)

        self._cleanup_threads()
        print("[🔴 DAEMON] Stopped.")

    def _process_syslog_queue(self) -> None:
        """Process all available syslog messages from queue and pipe to SharedMemory."""
        processed = 0
        while (processed < 100 and 
               not self._syslog_queue.empty() and 
               self.running and 
               not self.shutdown_event.is_set()):
            try:
                line = self._syslog_queue.get_nowait()
                parsed = parse_syslog_line(line)
                if parsed.get("message"):
                    event = Event(
                        timestamp=parsed.get("timestamp") or datetime.now().isoformat(),
                        source="syslog",
                        severity=normalize_severity(
                            parsed.get("priority", parsed.get("message", ""))
                        ),
                        message=parsed.get("message", ""),
                        raw=parsed.get("raw", ""),
                    )
                    
                    # 🚀 FIX: Envoi en temps réel des dictionnaires JSON à l'Agent Analyseur via SharedMemory
                    self.publish([event], "events_structured")
                    
                    relevant = self.detect_relevant([event])
                    if relevant:
                        self.publish(relevant, "pending_analysis")
                        self.status.events_relevant += 1
                        
                    self.status.events_processed += 1
                    print(
                        f"[🟢 EVENT] ID:{event.event_id[:8]} | "
                        f"sev:{event.severity:.2f} | "
                        f"{'⚠️ RELEVANT' if relevant else '   normal  '} | "
                        f"[{line[:50]}...]" if len(line) > 50 else f"[{line}]"
                    )
                    processed += 1
            except queue.Empty:
                break
            except Exception as e:
                print(f"[❌ ERROR] Syslog processing error: {e}")

    def _process_network_queue(self) -> None:
        """Process all available network packets from queue and pipe to SharedMemory."""
        processed = 0
        while (processed < 100 and
               not self._tshark_queue.empty() and
               self.running and
               not self.shutdown_event.is_set()):
            try:
                item_type, packet = self._tshark_queue.get_nowait()
                if item_type == "PACKET":
                    timestamp = packet.get("timestamp")
                    if timestamp is None:
                        timestamp = datetime.now().isoformat()
                    elif isinstance(timestamp, (int, float)):
                        try:
                            timestamp = datetime.fromtimestamp(timestamp).isoformat()
                        except (ValueError, OSError):
                            timestamp = datetime.now().isoformat()

                    message = (
                        f"{packet.get('protocol', 'unknown')} "
                        f"{packet.get('src_ip') or 'unknown'} -> "
                        f"{packet.get('dst_ip') or 'unknown'}"
                    )
                    event = Event(
                        timestamp=timestamp,
                        source="network",
                        severity=0.5,
                        message=message,
                        raw=json.dumps(packet.get("raw_packet", packet)),
                    )
                    
                    # 🚀 FIX: Stream direct à la Shared Memory en temps réel pour l'Analyseur
                    self.publish([event], "events_structured")
                    
                    # Les paquets réseaux peuvent aussi être analysés s'ils matchent des critères
                    relevant = self.detect_relevant([event])
                    if relevant:
                        self.publish(relevant, "pending_analysis")
                        
                    self.status.events_processed += 1
                    print(
                        f"[🟢 EVENT] ID:{event.event_id[:8]} | "
                        f"sev:{event.severity:.2f} | "
                        f"net | {event.message[:60]}"
                    )
                    processed += 1
            except queue.Empty:
                break
            except Exception as e:
                print(f"[❌ ERROR] Network processing error: {e}")

    def _cleanup_threads(self) -> None:
        """Clean up background threads gracefully."""
        if self.syslog_socket:
            try:
                self.syslog_socket.close()
            except Exception as e:
                print(f"[⚠️ WARNING] Error closing syslog socket: {e}")

    def collect_syslog(self, path: str = "data/raw/syslog.log") -> List[Event]:
        events = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    parsed = parse_syslog_line(line.strip())
                    if parsed.get("message"):
                        events.append(Event(
                            timestamp=parsed.get("timestamp", ""),
                            source="syslog",
                            severity=normalize_severity(
                                parsed.get("priority", parsed.get("message", ""))
                            ),
                            message=parsed.get("message", ""),
                            raw=parsed.get("raw", ""),
                        ))
        return events

    def collect_network(self, path: str = "data/raw/network_traffic.json") -> List[Event]:
        events = []
        if not os.path.exists(path):
            return events
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if line.strip():
                    try:
                        record = json.loads(line)
                        events.append(Event(
                            timestamp=record.get("timestamp", ""),
                            source="network",
                            severity=normalize_severity(record.get("severity", 0.5)),
                            message=json.dumps(record),
                            raw=json.dumps(record),
                        ))
                    except json.JSONDecodeError:
                        continue
        return events

    def collect_siem(self, path: str = "data/raw/siem_alerts.json") -> List[Event]:
        events = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                records = json.load(f)
            if isinstance(records, dict):
                records = [records]
            for record in records:
                events.append(Event(
                    timestamp=record.get("timestamp", ""),
                    source="siem",
                    severity=normalize_severity(record.get("severity", 0.5)),
                    message=record.get("message", ""),
                    raw=json.dumps(record),
                ))
        except Exception:
            pass
        return events

    def clean_and_structure(self, payload: List[Dict], source: str) -> List[Event]:
        seen_ids = set()
        events = []
        for item in payload:
            event = Event(
                timestamp=item.get("timestamp", ""),
                source=source,
                severity=normalize_severity(item.get("severity", 0.5)),
                message=item.get("message", ""),
                raw=item.get("raw", ""),
            )
            if event.event_id not in seen_ids:
                seen_ids.add(event.event_id)
                events.append(event)
        return events

    def detect_relevant(self, events: List[Event]) -> List[Event]:
        keywords = [
            "attaque", "critical", "erreur", "échec", "brute", "force", "intrusion",
            "attack", "error", "failure", "failed", "password", "invalid user",
            "ddos", "unauthorized", "denied"
        ]
        relevant = []
        for event in events:
            msg_lower = event.message.lower()
            if any(kw in msg_lower for kw in keywords) or event.severity >= 0.7:
                relevant.append(event)
        return relevant

    def publish(self, events: List[Event], channel: str = "pending_analysis") -> None:
        """Publie les événements normalisés formatés en JSON dictionnaire à la Shared Memory."""
        try:
            # 🚀 FIX: Utilisation de .to_json_dict() au lieu de __dict__ brut pour un transfert clean
            self.memory.write(channel, [e.to_json_dict() for e in events])
        except Exception as e:
            print(f"[❌ ERROR] Failed to publish to channel '{channel}': {e}")

    def get_status(self) -> Dict[str, Any]:
        return self.status.to_dict()

    def run(self) -> Dict[str, Any]:
        all_events = []
        all_events.extend(self.collect_syslog())
        all_events.extend(self.collect_network())
        all_events.extend(self.collect_siem())

        self.publish(all_events, "events_structured")
        relevant = self.detect_relevant(all_events)
        self.publish(relevant, "pending_analysis")

        return {
            "total_events": len(all_events),
            "relevant_events": len(relevant),
            "sources": list(set(e.source for e in all_events)),
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SecurityAgent - Log Ingestion & Traffic Monitoring")
    parser.add_argument("--daemon", action="store_true", help="Run in live daemon mode")
    parser.add_argument("--syslog-port", type=int, default=1514, help="Syslog port (UDP or TCP)")
    parser.add_argument("--syslog-tcp", action="store_true", help="Use TCP instead of UDP for syslog")
    parser.add_argument("--network-interface", help="Network interface for tshark")
    parser.add_argument("--network-filter", help="tshark capture filter (BPF syntax)")
    parser.add_argument("--cleanup", action="store_true", help="Clean data/raw/ before starting")
    args = parser.parse_args()

    agent = SecurityAgent(
        syslog_port=args.syslog_port,
        syslog_tcp=args.syslog_tcp,
        network_interface=args.network_interface,
        network_filter=args.network_filter,
    )

    if args.cleanup:
        removed = agent.cleanup()
        print(f"Cleaned {removed} files from data/raw/")

    if args.daemon:
        print("Starting SecurityAgent in LIVE DAEMON mode...")
        print(f"  - Syslog listener: {'TCP' if args.syslog_tcp else 'UDP'} port {args.syslog_port}")
        print(f"  - Network capture: interface={args.network_interface or 'auto-detected'}")
        agent.run_daemon()
    else:
        result = agent.run()
        print(json.dumps(result, indent=2))

ExtractorAgent = SecurityAgent