#!/usr/bin/env python3
"""
Demo Data Generator for Security Monitoring Dashboard
Generates realistic security events for demonstration purposes
"""

import random
import json
from datetime import datetime, timedelta
from faker import Faker
from typing import List, Dict
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.database.database import db_manager
from src.database.models import SecurityEvent, Incident, UserBaseline, ComplianceEvent
from src.detection.mitre_attack import MitreAttackFramework

fake = Faker()

class DemoDataGenerator:
    def __init__(self):
        self.mitre_framework = MitreAttackFramework()
        self.demo_users = [
            'alice.johnson', 'bob.smith', 'charlie.brown', 'diana.ross',
            'evan.wright', 'fiona.green', 'george.white', 'helen.clark',
            'ian.davis', 'julia.adams', 'admin', 'service_account'
        ]
        self.demo_hostnames = [
            'WS001', 'WS002', 'WS003', 'SRV-DB01', 'SRV-WEB01', 
            'SRV-DC01', 'LAP-001', 'LAP-002', 'DEV-001', 'TEST-SRV'
        ]
        self.demo_ips = [
            '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25',
            '192.168.1.100', '192.168.1.101', '10.0.0.50', '10.0.0.51',
            '172.16.1.10', '203.0.113.15'  # Some external IPs
        ]
        
    def generate_security_events(self, count: int = 1000, days_back: int = 30) -> List[SecurityEvent]:
        events = []
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)
        
        for _ in range(count):
            event_type = random.choice([
                'auth_success', 'auth_failure', 'windows_logon', 'windows_logon_failure',
                'file_access', 'process_execution', 'network_connection',
                'privilege_escalation', 'suspicious_activity'
            ])
            
            # Generate realistic timestamp (more events during business hours)
            event_time = fake.date_time_between(start_date=start_time, end_date=end_time)
            if 9 <= event_time.hour <= 17:  # Business hours
                weight = 3
            elif 18 <= event_time.hour <= 22:  # Evening
                weight = 2
            else:  # Night/early morning
                weight = 1
            
            # Adjust probability based on time
            if random.randint(1, 3) > weight:
                continue
                
            user_id = random.choice(self.demo_users) if random.random() > 0.1 else None
            source_ip = random.choice(self.demo_ips) if random.random() > 0.2 else None
            hostname = random.choice(self.demo_hostnames)
            
            # Generate risk score based on event type and context
            risk_score = self._calculate_demo_risk_score(event_type, user_id, event_time)
            
            # Add MITRE technique for higher risk events
            mitre_technique = None
            mitre_tactic = None
            if risk_score >= 5.0:
                technique = random.choice(list(self.mitre_framework.techniques.values()))
                mitre_technique = technique.technique_id
                mitre_tactic = technique.tactic.value
            
            event = SecurityEvent(
                timestamp=event_time,
                source_system=random.choice(['Windows Event Log', 'Linux Syslog', 'Network Device']),
                event_type=event_type,
                severity=self._risk_to_severity(risk_score),
                user_id=user_id,
                source_ip=source_ip,
                destination_ip=self._generate_destination_ip(source_ip),
                hostname=hostname,
                process_name=self._generate_process_name(event_type),
                command_line=self._generate_command_line(event_type),
                file_path=self._generate_file_path(event_type),
                event_description=self._generate_event_description(event_type, user_id, hostname),
                raw_log=self._generate_raw_log(event_type),
                risk_score=risk_score,
                mitre_technique=mitre_technique,
                mitre_tactic=mitre_tactic
            )
            
            events.append(event)
            
        return events
    
    def _calculate_demo_risk_score(self, event_type: str, user_id: str, timestamp: datetime) -> float:
        base_scores = {
            'auth_success': 1.0,
            'auth_failure': 4.0,
            'windows_logon': 1.5,
            'windows_logon_failure': 5.0,
            'file_access': 2.0,
            'process_execution': 3.0,
            'network_connection': 2.5,
            'privilege_escalation': 8.0,
            'suspicious_activity': 7.5
        }
        
        score = base_scores.get(event_type, 3.0)
        
        # Higher risk for admin accounts
        if user_id and 'admin' in user_id.lower():
            score += 2.0
            
        # Higher risk outside business hours
        if timestamp.hour < 7 or timestamp.hour > 19:
            score += 1.5
            
        # Weekend risk
        if timestamp.weekday() >= 5:
            score += 1.0
            
        # Add some randomness
        score += random.uniform(-1.0, 1.0)
        
        return max(0.0, min(10.0, score))
    
    def _risk_to_severity(self, risk_score: float) -> str:
        if risk_score >= 8.0:
            return 'critical'
        elif risk_score >= 6.0:
            return 'high'
        elif risk_score >= 3.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_destination_ip(self, source_ip: str) -> str:
        if random.random() < 0.3:  # 30% chance of external connection
            return fake.ipv4()
        else:
            return random.choice(self.demo_ips)
    
    def _generate_process_name(self, event_type: str) -> str:
        processes = {
            'auth_success': ['winlogon.exe', 'lsass.exe', 'svchost.exe'],
            'auth_failure': ['winlogon.exe', 'lsass.exe'],
            'process_execution': ['cmd.exe', 'powershell.exe', 'python.exe', 'notepad.exe', 'chrome.exe'],
            'privilege_escalation': ['psexec.exe', 'wmic.exe', 'powershell.exe', 'cmd.exe'],
            'suspicious_activity': ['powershell.exe', 'cmd.exe', 'net.exe', 'reg.exe']
        }
        
        if event_type in processes:
            return random.choice(processes[event_type])
        return fake.word() + '.exe'
    
    def _generate_command_line(self, event_type: str) -> str:
        if event_type == 'process_execution' or event_type == 'suspicious_activity':
            commands = [
                'powershell.exe -ExecutionPolicy Bypass -File script.ps1',
                'cmd.exe /c dir C:\\Users\\',
                'net user admin /add',
                'wmic process list',
                'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion',
                'systeminfo',
                'whoami /all'
            ]
            return random.choice(commands)
        return None
    
    def _generate_file_path(self, event_type: str) -> str:
        if event_type == 'file_access':
            paths = [
                'C:\\Users\\Documents\\sensitive.docx',
                'C:\\Program Files\\Application\\config.ini',
                'D:\\Data\\customer_data.xlsx',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\temp\\malware.exe'
            ]
            return random.choice(paths)
        return None
    
    def _generate_event_description(self, event_type: str, user_id: str, hostname: str) -> str:
        templates = {
            'auth_success': f"Successful authentication for user {user_id or 'unknown'} on {hostname}",
            'auth_failure': f"Failed authentication attempt for user {user_id or 'unknown'} on {hostname}",
            'process_execution': f"Process execution detected on {hostname}",
            'privilege_escalation': f"Potential privilege escalation detected on {hostname}",
            'suspicious_activity': f"Suspicious activity detected on {hostname}"
        }
        
        return templates.get(event_type, f"Security event of type {event_type} on {hostname}")
    
    def _generate_raw_log(self, event_type: str) -> str:
        return json.dumps({
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'raw_data': fake.text(max_nb_chars=200)
        })
    
    def generate_user_baselines(self) -> List[UserBaseline]:
        baselines = []
        
        for user in self.demo_users:
            if user in ['admin', 'service_account']:
                continue  # Skip system accounts
                
            baseline = UserBaseline(
                user_id=user,
                baseline_start_date=datetime.utcnow() - timedelta(days=30),
                baseline_end_date=datetime.utcnow(),
                typical_login_hours_start=random.randint(7, 9),
                typical_login_hours_end=random.randint(17, 19),
                common_source_ips=json.dumps(random.sample(self.demo_ips[:5], 2)),
                common_hostnames=json.dumps(random.sample(self.demo_hostnames[:5], 2)),
                average_daily_logins=random.randint(3, 12),
                common_applications=json.dumps(['outlook.exe', 'chrome.exe', 'excel.exe']),
                geographic_locations=json.dumps([{'country': 'US', 'city': 'New York'}]),
                privilege_level=random.choice(['user', 'power_user', 'admin']),
                department=random.choice(['IT', 'Finance', 'HR', 'Sales', 'Marketing']),
                last_updated=datetime.utcnow()
            )
            
            baselines.append(baseline)
            
        return baselines
    
    def generate_sample_incidents(self, count: int = 10) -> List[Incident]:
        incidents = []
        
        for i in range(count):
            severity = random.choice(['low', 'medium', 'high', 'critical'])
            risk_score = {
                'low': random.uniform(1, 3),
                'medium': random.uniform(3, 6),
                'high': random.uniform(6, 8),
                'critical': random.uniform(8, 10)
            }[severity]
            
            incident = Incident(
                incident_id=f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{i+1:04d}",
                title=f"Security Incident - {severity.title()} Risk Event",
                description=f"Automated detection of {severity} severity security event requiring investigation.",
                severity=severity,
                status=random.choice(['open', 'investigating', 'resolved']),
                created_timestamp=fake.date_time_between(start_date='-30d', end_date='now'),
                updated_timestamp=datetime.utcnow(),
                source_events_count=random.randint(1, 10),
                risk_score=risk_score,
                mitre_techniques=random.choice(['T1078', 'T1110', 'T1059', 'T1055']),
                affected_users=random.choice(self.demo_users),
                affected_systems=random.choice(self.demo_hostnames)
            )
            
            incidents.append(incident)
            
        return incidents
    
    def populate_database(self, events_count: int = 1000, days_back: int = 30):
        print(f"Generating {events_count} demo security events...")
        
        session = db_manager.get_session()
        try:
            # Generate and insert security events
            events = self.generate_security_events(events_count, days_back)
            for event in events:
                session.add(event)
            
            # Generate and insert user baselines
            print("Generating user baselines...")
            baselines = self.generate_user_baselines()
            for baseline in baselines:
                session.add(baseline)
            
            # Generate and insert sample incidents
            print("Generating sample incidents...")
            incidents = self.generate_sample_incidents()
            for incident in incidents:
                session.add(incident)
            
            session.commit()
            print(f"✅ Successfully generated:")
            print(f"   - {len(events)} security events")
            print(f"   - {len(baselines)} user baselines")
            print(f"   - {len(incidents)} incidents")
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error generating demo data: {e}")
            raise
        finally:
            session.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate demo data for Security Monitoring Dashboard')
    parser.add_argument('--events', type=int, default=1000, help='Number of security events to generate')
    parser.add_argument('--days', type=int, default=30, help='Number of days back to generate data')
    parser.add_argument('--reset', action='store_true', help='Reset database before generating data')
    
    args = parser.parse_args()
    
    # Initialize database
    if args.reset:
        print("Resetting database...")
        db_manager.create_tables()
    
    # Generate demo data
    generator = DemoDataGenerator()
    generator.populate_database(args.events, args.days)

if __name__ == "__main__":
    main()