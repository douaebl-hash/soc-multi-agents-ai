"""
Test script for ExtractorAgent syslog parsing.
Run AFTER starting the daemon in another terminal.
"""

import socket
import time

TEST_MESSAGES = [
    # RFC 3164 with priority
    b"<34>Jun 17 2026 15:25:00 arch-secure sshd[4321]: Failed password for invalid user admin from 192.168.1.100",
    b"<1>Jun 17 2026 15:26:00 arch-secure kernel: CRITICAL: intrusion detected on eth0",
    b"<14>Jun 17 2026 15:27:00 arch-secure nginx[999]: error 403 Forbidden from 10.0.0.5",
    b"<86>Jun 17 2026 15:28:00 arch-secure cron[111]: info: normal scheduled task ran ok",
    b"<34>Jun 17 2026 15:29:00 arch-secure sshd[4322]: Failed password for invalid user root from 192.168.1.200",
    b"<1>Jun 17 2026 15:30:00 arch-secure firewall: brute force attack detected from 172.16.0.99",
]

HOST = "127.0.0.1"
PORT = 1514

def test_parser_locally():
    """Test parse_syslog_line directly without network."""
    import sys, os
    sys.path.insert(0, os.getcwd())
    try:
        from agents.extracteur.utils.parsers import parse_syslog_line, normalize_severity
        print("=" * 60)
        print("LOCAL PARSER TEST")
        print("=" * 60)
        for msg in TEST_MESSAGES:
            line = msg.decode()
            parsed = parse_syslog_line(line)
            sev = normalize_severity(parsed.get("priority", parsed.get("message", "")))
            print(f"\nINPUT   : {line[:70]}...")
            print(f"HOST    : {parsed.get('host')}")
            print(f"PROCESS : {parsed.get('process')}")
            print(f"MESSAGE : {parsed.get('message')}")
            print(f"SEVERITY: {sev:.2f}")
            print(f"ERR     : {parsed.get('parse_error')}")
    except ImportError as e:
        print(f"Import error (run from project root): {e}")

def test_udp_send(delay: float = 0.5):
    """Send test packets to the running daemon."""
    print("\n" + "=" * 60)
    print(f"UDP SEND TEST → {HOST}:{PORT}")
    print("=" * 60)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i, msg in enumerate(TEST_MESSAGES, 1):
        s.sendto(msg, (HOST, PORT))
        print(f"[{i}/{len(TEST_MESSAGES)}] Sent: {msg[:60].decode()}...")
        time.sleep(delay)
    s.close()
    print("\nDone. Check daemon terminal for [🟢 EVENT EXTRACTED] lines.")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--local", action="store_true", help="Test parser locally (no daemon needed)")
    p.add_argument("--send", action="store_true", help="Send UDP packets to running daemon")
    p.add_argument("--all", action="store_true", help="Run both tests")
    args = p.parse_args()

    if args.local or args.all:
        test_parser_locally()
    if args.send or args.all:
        test_udp_send()
    if not any([args.local, args.send, args.all]):
        print("Usage: python3 test_syslog.py [--local] [--send] [--all]")
        print("  --local  Test the parser directly (no daemon needed)")
        print("  --send   Send UDP packets to running daemon")
        print("  --all    Run both")