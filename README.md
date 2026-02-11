# Security Monitor Tool

A legitimate security monitoring tool designed to monitor your own applications for security events and suspicious activities.

## Features

- **Real-time Log Monitoring**: Monitor application logs for security events
- **Pattern Detection**: Detect common attack patterns (SQL injection, XSS, brute force)
- **Configurable Rules**: Custom security rules with regex patterns
- **Alert System**: Email and webhook notifications for security events
- **Web Dashboard**: Real-time monitoring dashboard
- **Event Correlation**: Aggregate events based on thresholds and time windows

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Run Demo
```bash
python security_monitor_cli.py --demo
```

### 2. Start Web Dashboard
```bash
python web_dashboard.py
```
Access at http://localhost:5000

### 3. Monitor Log Files
```bash
python security_monitor_cli.py --log-file /path/to/access.log
```

## Configuration

The tool uses `security_config.json` for configuration:

```json
{
  "rules": [
    {
      "name": "Failed Login Attempts",
      "pattern": "failed.*login|authentication.*failed",
      "severity": "high",
      "threshold": 5,
      "time_window": 300,
      "enabled": true
    }
  ],
  "alerts": {
    "email_enabled": false,
    "email_recipients": ["admin@example.com"],
    "webhook_url": null,
    "smtp_server": "localhost",
    "smtp_port": 587
  }
}
```

## Security Rules

Built-in detection rules include:
- Failed login attempts
- SQL injection patterns
- XSS attack vectors
- Suspicious user agents
- Rate limiting violations

## Log Formats

Supports:
- Common Log Format (Apache/Nginx)
- JSON structured logs
- Custom formats via parsing functions

## Alerting

Configure email alerts or webhooks to get notified of security events:
- Email notifications via SMTP
- Slack/Discord webhooks
- Custom webhook endpoints

## API Endpoints

- `GET /api/events` - Retrieve security events
- `GET /api/stats` - Get monitoring statistics
- `POST /api/rules` - Add new security rules
- `POST /api/alert-config` - Update alert configuration

## Usage Examples

### Command Line Interface
```bash
# Monitor multiple log files
python security_monitor_cli.py --log-file access.log error.log

# Use custom config
python security_monitor_cli.py --config custom_config.json --log-file app.log

# Start web interface
python web_dashboard.py
```

### Programmatic Usage
```python
from security_monitor import SecurityMonitor, SecurityEvent
from datetime import datetime

# Create monitor instance
monitor = SecurityMonitor()

# Add security event
event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="authentication",
    severity="high",
    source="auth_service",
    message="Failed login attempt",
    details={"user": "admin", "ip": "192.168.1.100"},
    ip_address="192.168.1.100"
)

monitor.add_event(event)

# Get statistics
stats = monitor.get_statistics()
print(f"Total events: {stats['total_events']}")
```

## Security Best Practices

- Only monitor applications you own or have permission to monitor
- Secure the configuration files containing SMTP credentials
- Use HTTPS for webhook endpoints
- Regularly review and update detection rules
- Monitor the monitor itself (ensure the tool isn't compromised)

## File Structure

```
security_monitor.py          # Core monitoring engine
web_dashboard.py             # Flask web interface
security_monitor_cli.py      # Command-line interface
requirements.txt             # Python dependencies
templates/dashboard.html     # Web dashboard template
security_config.json         # Configuration file (auto-generated)
```

## License

This tool is designed for legitimate security monitoring of your own applications. Use responsibly and only on systems you have permission to monitor.