from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from src.database.models import SecurityEvent, UserBaseline
from src.database.database import db_manager
from .mitre_attack import MitreAttackFramework, MitreTactic
import logging
import ipaddress

logger = logging.getLogger(__name__)

class DetectionRule:
    def __init__(self, rule_id: str, name: str, description: str, mitre_technique: str, risk_score: float):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.mitre_technique = mitre_technique
        self.risk_score = risk_score
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        raise NotImplementedError

class BruteForceDetectionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R001",
            name="Brute Force Attack Detection",
            description="Detects multiple failed login attempts from same source",
            mitre_technique="T1110",
            risk_score=7.0
        )
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        if event.event_type not in ['auth_failure', 'windows_logon_failure']:
            return None
        
        # Look for multiple failed attempts in last 10 minutes
        time_threshold = datetime.utcnow() - timedelta(minutes=10)
        
        failed_attempts = session.query(SecurityEvent).filter(
            and_(
                SecurityEvent.timestamp >= time_threshold,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.event_type.in_(['auth_failure', 'windows_logon_failure'])
            )
        ).count()
        
        if failed_attempts >= 5:
            return {
                'rule_triggered': self.rule_id,
                'description': f"Brute force detected: {failed_attempts} failed attempts from {event.source_ip}",
                'risk_score': min(self.risk_score + (failed_attempts * 0.5), 10.0),
                'mitre_technique': self.mitre_technique,
                'evidence': f"Failed attempts: {failed_attempts}, Source IP: {event.source_ip}"
            }
        
        return None

class UnusualTimeAccessRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R002",
            name="Unusual Time Access",
            description="Detects logins outside of normal business hours",
            mitre_technique="T1078",
            risk_score=4.0
        )
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        if event.event_type not in ['auth_success', 'windows_logon'] or not event.user_id:
            return None
        
        # Check if login is outside business hours (9 AM - 6 PM)
        event_hour = event.timestamp.hour
        if 9 <= event_hour <= 18:
            return None
        
        # Get user baseline
        baseline = session.query(UserBaseline).filter(
            UserBaseline.user_id == event.user_id
        ).first()
        
        if baseline:
            # Check against user's typical hours
            if (baseline.typical_login_hours_start <= event_hour <= baseline.typical_login_hours_end):
                return None
        
        # Weekend check (Saturday=5, Sunday=6)
        if event.timestamp.weekday() >= 5:
            risk_multiplier = 1.5
        else:
            risk_multiplier = 1.0
        
        return {
            'rule_triggered': self.rule_id,
            'description': f"Unusual time access by {event.user_id} at {event.timestamp.strftime('%H:%M')}",
            'risk_score': self.risk_score * risk_multiplier,
            'mitre_technique': self.mitre_technique,
            'evidence': f"Login time: {event.timestamp}, User: {event.user_id}"
        }

class PrivilegeEscalationRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R003",
            name="Privilege Escalation Detection",
            description="Detects potential privilege escalation activities",
            mitre_technique="T1068",
            risk_score=8.0
        )
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        if not event.process_name:
            return None
        
        suspicious_processes = [
            'psexec', 'wmic', 'powershell', 'cmd', 'net', 'netsh',
            'reg', 'sc', 'tasklist', 'systeminfo', 'whoami'
        ]
        
        if any(proc in event.process_name.lower() for proc in suspicious_processes):
            # Check for suspicious command line arguments
            if event.command_line:
                suspicious_args = [
                    'net user', 'net localgroup', 'runas', 'elevate',
                    'bypass', 'unrestricted', 'hidden', '-enc', '-e '
                ]
                
                if any(arg in event.command_line.lower() for arg in suspicious_args):
                    return {
                        'rule_triggered': self.rule_id,
                        'description': f"Potential privilege escalation: {event.process_name}",
                        'risk_score': self.risk_score,
                        'mitre_technique': self.mitre_technique,
                        'evidence': f"Process: {event.process_name}, Command: {event.command_line}"
                    }
        
        return None

class SuspiciousNetworkActivityRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R004",
            name="Suspicious Network Activity",
            description="Detects unusual network connections and data transfers",
            mitre_technique="T1041",
            risk_score=6.0
        )
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        if not event.destination_ip:
            return None
        
        try:
            dest_ip = ipaddress.ip_address(event.destination_ip)
            
            # Check for connections to suspicious networks
            suspicious_networks = [
                ipaddress.ip_network('10.0.0.0/8'),  # Private networks (unusual for external comms)
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16')
            ]
            
            # Check for external connections from internal hosts
            if event.source_ip:
                try:
                    src_ip = ipaddress.ip_address(event.source_ip)
                    if src_ip.is_private and not dest_ip.is_private:
                        # External connection - check for suspicious ports/protocols
                        suspicious_ports = ['4444', '1337', '31337', '8080', '443']
                        if any(port in str(event.raw_log) for port in suspicious_ports):
                            return {
                                'rule_triggered': self.rule_id,
                                'description': f"Suspicious external connection from {event.source_ip} to {event.destination_ip}",
                                'risk_score': self.risk_score,
                                'mitre_technique': self.mitre_technique,
                                'evidence': f"Source: {event.source_ip}, Destination: {event.destination_ip}"
                            }
                except:
                    pass
            
        except:
            pass
        
        return None

class DataExfiltrationRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="R005",
            name="Data Exfiltration Detection",
            description="Detects potential data exfiltration activities",
            mitre_technique="T1041",
            risk_score=8.5
        )
    
    def evaluate(self, event: SecurityEvent, session: Session) -> Optional[Dict]:
        if not event.user_id:
            return None
        
        # Look for large file access patterns in last hour
        time_threshold = datetime.utcnow() - timedelta(hours=1)
        
        file_access_count = session.query(SecurityEvent).filter(
            and_(
                SecurityEvent.timestamp >= time_threshold,
                SecurityEvent.user_id == event.user_id,
                SecurityEvent.event_type == 'file_access',
                SecurityEvent.file_path.isnot(None)
            )
        ).count()
        
        if file_access_count >= 50:
            return {
                'rule_triggered': self.rule_id,
                'description': f"Potential data exfiltration: {file_access_count} file accesses by {event.user_id}",
                'risk_score': self.risk_score,
                'mitre_technique': self.mitre_technique,
                'evidence': f"File accesses: {file_access_count}, User: {event.user_id}, Time window: 1 hour"
            }
        
        return None

class DetectionEngine:
    def __init__(self):
        self.mitre_framework = MitreAttackFramework()
        self.rules = [
            BruteForceDetectionRule(),
            UnusualTimeAccessRule(),
            PrivilegeEscalationRule(),
            SuspiciousNetworkActivityRule(),
            DataExfiltrationRule()
        ]
        logger.info(f"Detection engine initialized with {len(self.rules)} rules")
    
    def evaluate_event(self, event: SecurityEvent) -> List[Dict]:
        detections = []
        session = db_manager.get_session()
        
        try:
            for rule in self.rules:
                try:
                    detection = rule.evaluate(event, session)
                    if detection:
                        detection['rule_name'] = rule.name
                        detection['timestamp'] = datetime.utcnow()
                        detections.append(detection)
                        logger.info(f"Detection triggered: {rule.name} for event {event.id}")
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
            
        finally:
            session.close()
        
        return detections
    
    def get_rule_by_id(self, rule_id: str) -> Optional[DetectionRule]:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None