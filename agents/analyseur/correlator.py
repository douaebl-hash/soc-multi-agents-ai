"""
correlator.py
Temporal correlation engine for Agent Analyseur.
Detects multi-source attack patterns (e.g. port scan + failed SSH = intrusion).
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

CORRELATION_WINDOW_SECONDS = 300   # 5-minute sliding window
BRUTE_FORCE_THRESHOLD      = 5     # N failed auths from same IP -> alert
SCAN_THRESHOLD             = 25    # N distinct destinations from same IP -> port scan confirmed
                                     # (normal browsing easily touches 5-10 CDN/ad hosts per
                                     # page load, so this must be well above that)


class CorrelationEngine:
    """
    Maintains a sliding window of events per source IP, in memory.
    Detects:
      1. Brute-force: multiple failed auths from same IP
      2. Port scan confirmed by repeated network events
      3. COMBINED: scan + brute-force -> HIGH-CONFIDENCE intrusion -> CRITICAL
    """

    def __init__(self):
        self._window: dict = defaultdict(list)

    def _purge_old_events(self, ip: str, reference_time: datetime = None):
        """
        Remove events older than the window, relative to reference_time
        (the timestamp of the event currently being added) rather than
        real wall-clock time. This makes correlation correct both for
        live events and for historical/test timestamps.
        """
        if reference_time is None:
            reference_time = datetime.utcnow()
        cutoff = reference_time - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        self._window[ip] = [e for e in self._window[ip] if e["timestamp"] >= cutoff]

    def add_event(self, enriched_event: dict) -> Optional[dict]:
        """
        Feed an enriched event (output of rules_engine.analyze_event).
        Returns a correlation alert dict if a pattern is detected, else None.
        """
        entities = enriched_event.get("entities", {})
        ips = entities.get("ips", [])
        event_type = enriched_event.get("event_type", "UNKNOWN")
        source = enriched_event.get("source", "")
        event_id = enriched_event.get("event_id", "")

        ts_raw = enriched_event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            ts = datetime.utcnow()

        alerts = []
        for ip in ips:
            self._purge_old_events(ip, reference_time=ts)
            # destination = the OTHER ip in this event's entity list (best-effort)
            other_ips = [x for x in ips if x != ip]
            dest = other_ips[0] if other_ips else None
            self._window[ip].append({
                "timestamp": ts,
                "source": source,
                "event_type": event_type,
                "event_id": event_id,
                "dest": dest,
            })
            alert = self._check_patterns(ip)
            if alert:
                alerts.append(alert)

        if not alerts:
            return None
        return sorted(alerts, key=lambda a: a["correlation_severity"], reverse=True)[0]

    def _check_patterns(self, ip: str) -> Optional[dict]:
        events = self._window[ip]
        failed_auths = [e for e in events if e["event_type"] == "BRUTE_FORCE_ATTEMPT"]
        network_scans = [e for e in events if e["event_type"] == "PORT_SCAN"]
        syslog_events = [e for e in events if e["source"] == "syslog"]
        net_events = [e for e in events if e["source"] == "network"]

        if len(failed_auths) >= BRUTE_FORCE_THRESHOLD:
            return self._build_alert(
                ip, "BRUTE_FORCE_CONFIRMED",
                f"IP {ip} made {len(failed_auths)} failed auth attempts in {CORRELATION_WINDOW_SECONDS}s",
                0.85, [e["event_id"] for e in failed_auths],
            )

        if network_scans and syslog_events:
            return self._build_alert(
                ip, "INTRUSION_ATTEMPT",
                f"IP {ip} performed a port scan (network) AND authentication attempts (syslog) - HIGH-CONFIDENCE attack",
                1.0, [e["event_id"] for e in events],
            )

        # A real port scan means hitting MANY DISTINCT destinations/ports,
        # not just generating a lot of packets to a single server (which is
        # normal sustained traffic, e.g. an active app session).
        distinct_destinations = set(
            e.get("dest") for e in net_events if e.get("dest")
        )
        if len(distinct_destinations) >= SCAN_THRESHOLD:
            return self._build_alert(
                ip, "PORT_SCAN_CONFIRMED",
                f"IP {ip} hit {len(distinct_destinations)} distinct destinations - port scan confirmed",
                0.75, [e["event_id"] for e in net_events],
            )

        return None

    def _build_alert(self, ip, pattern, description, severity, involved_event_ids) -> dict:
        return {
            "alert_type": "CORRELATION_ALERT",
            "pattern": pattern,
            "attacker_ip": ip,
            "description": description,
            "correlation_severity": severity,
            "severity_label": _severity_label(severity),
            "involved_event_ids": involved_event_ids,
            "detected_at": datetime.utcnow().isoformat(),
        }


def _severity_label(score: float) -> str:
    if score >= 1.0: return "CRITICAL"
    if score >= 0.85: return "HIGH"
    if score >= 0.7: return "MEDIUM"
    return "LOW"