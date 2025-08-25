import pytest
from unittest.mock import Mock, patch
from src.collectors.base_collector import BaseCollector
from src.collectors.syslog_collector import SyslogCollector
from datetime import datetime

class TestBaseCollector:
    def test_normalize_event_with_complete_data(self):
        collector = BaseCollector("Test", {})
        
        raw_event = {
            'timestamp': '2024-01-01T12:00:00Z',
            'event_type': 'test_event',
            'user': 'testuser',
            'source_ip': '192.168.1.100',
            'hostname': 'test-host',
            'message': 'Test event message'
        }
        
        normalized = collector.normalize_event(raw_event)
        
        assert normalized['source_system'] == 'Test'
        assert normalized['event_type'] == 'test_event'
        assert normalized['user_id'] == 'testuser'
        assert normalized['source_ip'] == '192.168.1.100'
        assert normalized['hostname'] == 'test-host'
        assert normalized['risk_score'] == 0.0

class TestSyslogCollector:
    def setup_method(self):
        self.config = {
            'log_paths': ['/tmp/test_auth.log']
        }
        self.collector = SyslogCollector(self.config)
    
    def test_parse_ssh_success_log(self):
        log_line = "Jan 15 10:30:15 webserver sshd[12345]: Accepted publickey for admin from 192.168.1.50 port 54321 ssh2"
        
        result = self.collector._parse_syslog_line(log_line)
        
        assert result['process_name'] == 'sshd'
        assert result['event_type'] == 'auth_success'
        assert result['severity'] == 'low'
        assert result['user'] == 'admin'
        assert result['hostname'] == 'webserver'
    
    def test_parse_ssh_failure_log(self):
        log_line = "Jan 15 10:30:15 webserver sshd[12345]: Failed password for invalid user hacker from 192.168.1.200"
        
        result = self.collector._parse_syslog_line(log_line)
        
        assert result['process_name'] == 'sshd'
        assert result['event_type'] == 'auth_failure'
        assert result['severity'] == 'medium'
        assert result['user'] == 'hacker'