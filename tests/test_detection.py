import pytest
from datetime import datetime, timedelta
from src.detection.detection_rules import BruteForceDetectionRule, UnusualTimeAccessRule
from src.database.models import SecurityEvent, UserBaseline
from unittest.mock import Mock, MagicMock

class TestBruteForceDetectionRule:
    def setup_method(self):
        self.rule = BruteForceDetectionRule()
        
    def test_no_detection_for_non_auth_event(self):
        event = Mock()
        event.event_type = 'file_access'
        session = Mock()
        
        result = self.rule.evaluate(event, session)
        assert result is None
    
    def test_detection_for_multiple_failures(self):
        event = Mock()
        event.event_type = 'auth_failure'
        event.source_ip = '192.168.1.100'
        event.timestamp = datetime.utcnow()
        
        session = Mock()
        session.query.return_value.filter.return_value.count.return_value = 6
        
        result = self.rule.evaluate(event, session)
        
        assert result is not None
        assert result['rule_triggered'] == 'R001'
        assert 'Brute force detected' in result['description']
        assert result['risk_score'] >= 7.0

class TestUnusualTimeAccessRule:
    def setup_method(self):
        self.rule = UnusualTimeAccessRule()
    
    def test_no_detection_during_business_hours(self):
        event = Mock()
        event.event_type = 'auth_success'
        event.user_id = 'testuser'
        event.timestamp = datetime.now().replace(hour=14)  # 2 PM
        
        session = Mock()
        result = self.rule.evaluate(event, session)
        assert result is None
    
    def test_detection_outside_business_hours(self):
        event = Mock()
        event.event_type = 'auth_success'
        event.user_id = 'testuser'
        event.timestamp = datetime.now().replace(hour=2)  # 2 AM
        
        session = Mock()
        session.query.return_value.filter.return_value.first.return_value = None
        
        result = self.rule.evaluate(event, session)
        
        assert result is not None
        assert result['rule_triggered'] == 'R002'
        assert 'Unusual time access' in result['description']