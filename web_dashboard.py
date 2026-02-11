from flask import Flask, render_template, jsonify, request
from security_monitor import SecurityMonitor, SecurityEvent
from datetime import datetime, timedelta
import json
from threading import Thread
import time

app = Flask(__name__)
monitor = SecurityMonitor()

@app.route('/')
def dashboard():
    stats = monitor.get_statistics()
    recent_events = sorted(monitor.events[-50:], key=lambda x: x.timestamp, reverse=True)
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_events=recent_events,
                         rules=monitor.rules)

@app.route('/api/events')
def get_events():
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity')
    
    events = monitor.events.copy()
    
    if severity:
        events = [e for e in events if e.severity == severity]
    
    events = sorted(events, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    return jsonify([{
        'timestamp': e.timestamp.isoformat(),
        'event_type': e.event_type,
        'severity': e.severity,
        'source': e.source,
        'message': e.message,
        'details': e.details,
        'ip_address': e.ip_address,
        'user_id': e.user_id
    } for e in events])

@app.route('/api/stats')
def get_stats():
    return jsonify(monitor.get_statistics())

@app.route('/api/rules', methods=['GET', 'POST'])
def manage_rules():
    if request.method == 'POST':
        rule_data = request.json
        from security_monitor import MonitoringRule
        
        new_rule = MonitoringRule(**rule_data)
        monitor.rules.append(new_rule)
        monitor.save_config()
        
        return jsonify({'status': 'success', 'message': 'Rule added'})
    
    return jsonify([{
        'name': r.name,
        'pattern': r.pattern,
        'severity': r.severity,
        'threshold': r.threshold,
        'time_window': r.time_window,
        'enabled': r.enabled,
        'description': r.description
    } for r in monitor.rules])

@app.route('/api/alert-config', methods=['GET', 'POST'])
def manage_alerts():
    if request.method == 'POST':
        alert_data = request.json
        monitor.alert_config.__dict__.update(alert_data)
        monitor.save_config()
        return jsonify({'status': 'success'})
    
    return jsonify(monitor.alert_config.__dict__)

def create_sample_config():
    config = {
        "rules": [
            {
                "name": "Failed Login Attempts",
                "pattern": "failed.*login|authentication.*failed",
                "severity": "high",
                "threshold": 5,
                "time_window": 300,
                "enabled": True,
                "description": "Multiple failed login attempts detected"
            },
            {
                "name": "SQL Injection Pattern",
                "pattern": "union.*select|drop.*table|insert.*into",
                "severity": "critical",
                "threshold": 1,
                "time_window": 60,
                "enabled": True,
                "description": "Potential SQL injection detected"
            }
        ],
        "alerts": {
            "email_enabled": False,
            "email_recipients": ["admin@example.com"],
            "webhook_url": None,
            "smtp_server": "localhost",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": ""
        }
    }
    
    with open('security_config.json', 'w') as f:
        json.dump(config, f, indent=2)

if __name__ == '__main__':
    create_sample_config()
    app.run(debug=True, host='0.0.0.0', port=5000)