import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import hashlib
import threading
import time

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    message: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None

@dataclass
class MonitoringRule:
    name: str
    pattern: str
    severity: str
    threshold: int = 1
    time_window: int = 300
    enabled: bool = True
    description: str = ""

@dataclass
class AlertConfig:
    email_enabled: bool = False
    email_recipients: List[str] = None
    webhook_url: Optional[str] = None
    smtp_server: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""

class SecurityMonitor:
    def __init__(self, config_path: str = "security_config.json"):
        self.logger = self._setup_logging()
        self.config_path = config_path
        self.rules = []
        self.alert_config = AlertConfig()
        self.events = []
        self.event_counts = {}
        self.running = False
        self._load_config()
    
    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_monitor.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _load_config(self):
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    rules_data = config.get('rules', [])
                    self.rules = [MonitoringRule(**rule) for rule in rules_data]
                    
                    alert_data = config.get('alerts', {})
                    if alert_data:
                        self.alert_config = AlertConfig(**alert_data)
            
            if not self.rules:
                self._load_default_rules()
                
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self._load_default_rules()
    
    def _load_default_rules(self):
        default_rules = [
            MonitoringRule(
                name="Failed Login Attempts",
                pattern=r"failed.*login|authentication.*failed",
                severity="high",
                threshold=5,
                time_window=300,
                description="Multiple failed login attempts detected"
            ),
            MonitoringRule(
                name="SQL Injection Pattern",
                pattern=r"union.*select|drop.*table|insert.*into",
                severity="critical",
                threshold=1,
                time_window=60,
                description="Potential SQL injection detected"
            ),
            MonitoringRule(
                name="XSS Pattern",
                pattern=r"<script|javascript:|onload=|onerror=",
                severity="high",
                threshold=1,
                time_window=60,
                description="Potential XSS attack detected"
            ),
            MonitoringRule(
                name="Suspicious User Agent",
                pattern=r"sqlmap|nikto|nmap|burp",
                severity="medium",
                threshold=1,
                time_window=60,
                description="Suspicious user agent detected"
            ),
            MonitoringRule(
                name="Rate Limiting",
                pattern=r"too.*many.*requests|rate.*limit",
                severity="medium",
                threshold=10,
                time_window=60,
                description="Rate limit exceeded"
            )
        ]
        self.rules = default_rules
    
    def add_event(self, event: SecurityEvent):
        self.events.append(event)
        self._analyze_event(event)
        
        if len(self.events) > 10000:
            self.events = self.events[-5000:]
    
    def _analyze_event(self, event: SecurityEvent):
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._matches_rule(event, rule):
                key = f"{rule.name}_{event.source}"
                current_time = datetime.now()
                
                if key not in self.event_counts:
                    self.event_counts[key] = []
                
                self.event_counts[key].append(current_time)
                
                self.event_counts[key] = [
                    ts for ts in self.event_counts[key] 
                    if current_time - ts < timedelta(seconds=rule.time_window)
                ]
                
                if len(self.event_counts[key]) >= rule.threshold:
                    self._trigger_alert(event, rule)
                    self.event_counts[key] = []
    
    def _matches_rule(self, event: SecurityEvent, rule: MonitoringRule) -> bool:
        text_to_check = f"{event.message} {event.details.get('user_agent', '')}".lower()
        return bool(re.search(rule.pattern, text_to_check, re.IGNORECASE))
    
    def _trigger_alert(self, event: SecurityEvent, rule: MonitoringRule):
        alert_message = f"""
SECURITY ALERT: {rule.name}
Severity: {rule.severity.upper()}
Time: {event.timestamp}
Source: {event.source}
IP: {event.ip_address}
Message: {event.message}
Details: {json.dumps(event.details, indent=2)}
        """
        
        self.logger.warning(alert_message)
        
        if self.alert_config.email_enabled:
            self._send_email_alert(alert_message, rule)
        
        if self.alert_config.webhook_url:
            self._send_webhook_alert(event, rule)
    
    def _send_email_alert(self, message: str, rule: MonitoringRule):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.alert_config.smtp_username
            msg['Subject'] = f"Security Alert: {rule.name}"
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(self.alert_config.smtp_server, self.alert_config.smtp_port)
            server.starttls()
            server.login(self.alert_config.smtp_username, self.alert_config.smtp_password)
            
            for recipient in self.alert_config.email_recipients:
                msg['To'] = recipient
                server.send_message(msg)
                del msg['To']
            
            server.quit()
            self.logger.info(f"Email alert sent for rule: {rule.name}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def _send_webhook_alert(self, event: SecurityEvent, rule: MonitoringRule):
        try:
            payload = {
                "alert_type": "security",
                "rule": rule.name,
                "severity": rule.severity,
                "timestamp": event.timestamp.isoformat(),
                "event": asdict(event)
            }
            
            response = requests.post(
                self.alert_config.webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            self.logger.info(f"Webhook alert sent for rule: {rule.name}")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
    
    def parse_log_line(self, log_line: str, log_format: str = "common") -> Optional[SecurityEvent]:
        try:
            if log_format == "common":
                parts = log_line.split(' ')
                if len(parts) >= 7:
                    ip = parts[0]
                    timestamp_str = f"{parts[3]} {parts[4]}"
                    timestamp = datetime.strptime(timestamp_str, "[%d/%b/%Y:%H:%M:%S %z]")
                    method = parts[5].strip('"')
                    path = parts[6]
                    status = parts[8] if len(parts) > 8 else "unknown"
                    
                    message = f"{method} {path} - {status}"
                    
                    return SecurityEvent(
                        timestamp=timestamp,
                        event_type="access_log",
                        severity="info",
                        source="web_server",
                        message=message,
                        details={"method": method, "path": path, "status": status},
                        ip_address=ip
                    )
            
            elif log_format == "json":
                data = json.loads(log_line)
                return SecurityEvent(
                    timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
                    event_type=data.get('event_type', 'application'),
                    severity=data.get('severity', 'info'),
                    source=data.get('source', 'application'),
                    message=data.get('message', ''),
                    details=data.get('details', {}),
                    ip_address=data.get('ip_address'),
                    user_id=data.get('user_id'),
                    session_id=data.get('session_id')
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse log line: {e}")
            
        return None
    
    def monitor_log_file(self, file_path: str, log_format: str = "common"):
        try:
            with open(file_path, 'r') as f:
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        event = self.parse_log_line(line.strip(), log_format)
                        if event:
                            self.add_event(event)
                    else:
                        time.sleep(0.1)
                        
        except Exception as e:
            self.logger.error(f"Error monitoring log file: {e}")
    
    def start_monitoring(self, log_files: Dict[str, str] = None):
        self.running = True
        self.logger.info("Starting security monitoring...")
        
        if log_files:
            threads = []
            for file_path, log_format in log_files.items():
                thread = threading.Thread(
                    target=self.monitor_log_file,
                    args=(file_path, log_format)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            return threads
    
    def stop_monitoring(self):
        self.running = False
        self.logger.info("Stopping security monitoring...")
    
    def get_statistics(self) -> Dict[str, Any]:
        severity_counts = {}
        source_counts = {}
        
        for event in self.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            source_counts[event.source] = source_counts.get(event.source, 0) + 1
        
        return {
            "total_events": len(self.events),
            "severity_distribution": severity_counts,
            "source_distribution": source_counts,
            "active_rules": len([r for r in self.rules if r.enabled]),
            "total_rules": len(self.rules)
        }
    
    def save_config(self):
        config = {
            "rules": [asdict(rule) for rule in self.rules],
            "alerts": asdict(self.alert_config)
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        
        self.logger.info(f"Configuration saved to {self.config_path}")