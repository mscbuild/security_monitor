#!/usr/bin/env python3

from security_monitor import SecurityMonitor, SecurityEvent
from datetime import datetime
import json
import time
import argparse
import signal
import sys

def create_test_events():
    test_events = [
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="authentication",
            severity="high",
            source="auth_service",
            message="Failed login attempt for user admin",
            details={"user": "admin", "ip": "192.168.1.100"},
            ip_address="192.168.1.100",
            user_id="admin"
        ),
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="web_access",
            severity="critical",
            source="web_server",
            message="SQL injection attempt detected",
            details={"method": "POST", "path": "/login", "payload": "' OR '1'='1"},
            ip_address="10.0.0.50"
        ),
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="web_access",
            severity="high",
            source="web_server",
            message="XSS attempt detected",
            details={"method": "GET", "path": "/search", "query": "<script>alert('xss')</script>"},
            ip_address="10.0.0.75"
        ),
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="authentication",
            severity="medium",
            source="auth_service",
            message="Suspicious user agent detected",
            details={"user_agent": "sqlmap/1.6.12"},
            ip_address="10.0.0.25"
        )
    ]
    return test_events

def demo_monitoring():
    print("🔒 Security Monitor Demo")
    print("=" * 50)
    
    monitor = SecurityMonitor()
    
    print("\n1. Adding test security events...")
    events = create_test_events()
    for event in events:
        monitor.add_event(event)
    
    print("\n2. Current statistics:")
    stats = monitor.get_statistics()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for sub_key, sub_value in value.items():
                print(f"     {sub_key}: {sub_value}")
        else:
            print(f"   {key}: {value}")
    
    print("\n3. Active monitoring rules:")
    for rule in monitor.rules:
        print(f"   • {rule.name} ({rule.severity}) - Pattern: {rule.pattern}")
        print(f"     Threshold: {rule.threshold} in {rule.time_window}s")
    
    print("\n4. Sample log monitoring:")
    sample_logs = [
        '192.168.1.100 - - [10/Feb/2026:14:30:25 +0000] "POST /login HTTP/1.1" 401 532',
        '10.0.0.50 - - [10/Feb/2026:14:31:10 +0000] "POST /login HTTP/1.1" 200 1024',
        '{"timestamp": "2026-02-10T14:32:00", "event_type": "authentication", "severity": "high", "message": "Failed login attempt", "ip_address": "192.168.1.200"}'
    ]
    
    for log in sample_logs:
        if log.strip().startswith('{'):
            event = monitor.parse_log_line(log, "json")
        else:
            event = monitor.parse_log_line(log, "common")
        
        if event:
            monitor.add_event(event)
            print(f"   Parsed: {event.message} ({event.severity})")
    
    print("\n5. Final statistics after processing logs:")
    final_stats = monitor.get_statistics()
    print(f"   Total events processed: {final_stats['total_events']}")
    print(f"   Severity distribution: {final_stats['severity_distribution']}")
    
    print("\n✅ Demo completed successfully!")
    print("\nTo start the web dashboard, run:")
    print("   python web_dashboard.py")
    print("\nTo monitor log files in real-time:")
    print("   python security_monitor_cli.py --log-file /path/to/access.log")

def monitor_files(monitor, log_files):
    print(f"🔍 Starting file monitoring...")
    print(f"Monitoring {len(log_files)} log file(s)")
    
    threads = monitor.start_monitoring(log_files)
    
    try:
        print("Press Ctrl+C to stop monitoring...")
        while True:
            time.sleep(5)
            stats = monitor.get_statistics()
            print(f"Events processed: {stats['total_events']} | Active alerts: {len(monitor.event_counts)}")
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        print("Monitoring stopped.")

def main():
    parser = argparse.ArgumentParser(description="Security Monitor CLI")
    parser.add_argument("--demo", action="store_true", help="Run demo with test data")
    parser.add_argument("--log-file", nargs="+", help="Log files to monitor")
    parser.add_argument("--config", default="security_config.json", help="Configuration file path")
    parser.add_argument("--web", action="store_true", help="Start web dashboard")
    
    args = parser.parse_args()
    
    if args.demo:
        demo_monitoring()
    elif args.web:
        print("🌐 Starting web dashboard...")
        print("Dashboard will be available at: http://localhost:5000")
        try:
            import web_dashboard
        except ImportError:
            print("Error: Flask not installed. Install with: pip install flask")
    elif args.log_file:
        monitor = SecurityMonitor(args.config)
        
        log_files = {}
        for log_file in args.log_file:
            if log_file.endswith('.json'):
                log_files[log_file] = "json"
            else:
                log_files[log_file] = "common"
        
        monitor_files(monitor, log_files)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python security_monitor_cli.py --demo")
        print("  python security_monitor_cli.py --log-file /var/log/access.log")
        print("  python security_monitor_cli.py --web")

if __name__ == "__main__":
    main()
    
