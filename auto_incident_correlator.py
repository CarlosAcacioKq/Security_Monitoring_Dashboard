#!/usr/bin/env python3
"""
Automated Incident Correlation Engine
Automatically generates incidents from real security events using API threat intelligence
No manual templates - pure algorithmic correlation
"""

import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
import json

sys.path.append(os.path.join(os.path.dirname(__file__)))
from src.database.database import db_manager
from src.database.models import SecurityEvent, Incident

class AutomatedIncidentCorrelator:
    """Automatically correlate security events into incidents using real API data"""
    
    def __init__(self):
        self.session = db_manager.get_session()
        self.correlation_rules = {
            'ip_clustering': {
                'min_events': 3,
                'time_window_hours': 24,
                'risk_threshold': 6.0
            },
            'user_anomaly': {
                'min_events': 2,
                'time_window_hours': 8,
                'risk_threshold': 7.0
            },
            'mitre_pattern': {
                'min_techniques': 2,
                'time_window_hours': 12,
                'risk_threshold': 6.5
            }
        }
    
    def find_ip_based_incidents(self):
        """Find incidents based on multiple events from same malicious IP"""
        print("Analyzing IP-based event clustering...")
        
        # Get all events from real threat intelligence in last 24 hours
        time_threshold = datetime.utcnow() - timedelta(hours=24)
        
        events = self.session.query(SecurityEvent).filter(
            SecurityEvent.source_system == 'Real Threat Intelligence API',
            SecurityEvent.timestamp >= time_threshold,
            SecurityEvent.source_ip.isnot(None)
        ).all()
        
        # Group events by IP
        ip_events = defaultdict(list)
        for event in events:
            ip_events[event.source_ip].append(event)
        
        incidents = []
        for ip, event_list in ip_events.items():
            if len(event_list) >= self.correlation_rules['ip_clustering']['min_events']:
                avg_risk = sum(e.risk_score for e in event_list) / len(event_list)
                
                if avg_risk >= self.correlation_rules['ip_clustering']['risk_threshold']:
                    incident = self.create_ip_incident(ip, event_list, avg_risk)
                    incidents.append(incident)
        
        return incidents
    
    def find_user_based_incidents(self):
        """Find incidents based on user behavior anomalies with threat IPs"""
        print("Analyzing user-based threat interactions...")
        
        time_threshold = datetime.utcnow() - timedelta(hours=8)
        
        events = self.session.query(SecurityEvent).filter(
            SecurityEvent.source_system == 'Real Threat Intelligence API',
            SecurityEvent.timestamp >= time_threshold,
            SecurityEvent.user_id.isnot(None),
            SecurityEvent.risk_score >= 7.0  # High risk only
        ).all()
        
        # Group by user
        user_events = defaultdict(list)
        for event in events:
            user_events[event.user_id].append(event)
        
        incidents = []
        for user, event_list in user_events.items():
            if len(event_list) >= self.correlation_rules['user_anomaly']['min_events']:
                max_risk = max(e.risk_score for e in event_list)
                
                if max_risk >= self.correlation_rules['user_anomaly']['risk_threshold']:
                    incident = self.create_user_incident(user, event_list, max_risk)
                    incidents.append(incident)
        
        return incidents
    
    def find_mitre_pattern_incidents(self):
        """Find incidents based on MITRE ATT&CK technique patterns"""
        print("Analyzing MITRE ATT&CK technique patterns...")
        
        time_threshold = datetime.utcnow() - timedelta(hours=12)
        
        events = self.session.query(SecurityEvent).filter(
            SecurityEvent.source_system == 'Real Threat Intelligence API',
            SecurityEvent.timestamp >= time_threshold,
            SecurityEvent.mitre_technique.isnot(None)
        ).all()
        
        # Group by host/IP combination to find attack chains
        attack_chains = defaultdict(list)
        for event in events:
            key = f"{event.hostname}_{event.source_ip}"
            attack_chains[key].append(event)
        
        incidents = []
        for chain_key, event_list in attack_chains.items():
            unique_techniques = set(e.mitre_technique for e in event_list if e.mitre_technique)
            
            if len(unique_techniques) >= self.correlation_rules['mitre_pattern']['min_techniques']:
                avg_risk = sum(e.risk_score for e in event_list) / len(event_list)
                
                if avg_risk >= self.correlation_rules['mitre_pattern']['risk_threshold']:
                    incident = self.create_mitre_incident(chain_key, event_list, list(unique_techniques), avg_risk)
                    incidents.append(incident)
        
        return incidents
    
    def create_ip_incident(self, ip, events, avg_risk):
        """Create incident for IP-based correlation"""
        event_types = list(set(e.event_type for e in events))
        severities = list(set(e.severity for e in events))
        
        # Determine severity based on risk and event types
        if avg_risk >= 8.5 or 'critical' in severities:
            severity = 'critical'
        elif avg_risk >= 7.0 or 'high' in severities:
            severity = 'high'
        else:
            severity = 'medium'
        
        title = f"Multiple Security Events from Threat IP {ip}"
        description = f"Automated correlation detected {len(events)} security events from malicious IP {ip} within 24 hours. " \
                     f"Event types: {', '.join(event_types)}. " \
                     f"Average risk score: {avg_risk:.1f}. " \
                     f"Source: Real threat intelligence API correlation."
        
        return {
            'title': title,
            'description': description,
            'severity': severity,
            'risk_score': round(avg_risk, 1),
            'source_events': events,
            'correlation_type': 'ip_clustering',
            'threat_indicators': {'malicious_ip': ip}
        }
    
    def create_user_incident(self, user, events, max_risk):
        """Create incident for user-based correlation"""
        unique_ips = list(set(e.source_ip for e in events))
        event_types = list(set(e.event_type for e in events))
        
        severity = 'critical' if max_risk >= 8.5 else 'high'
        
        title = f"User {user} Interacting with Multiple Threat IPs"
        description = f"Automated correlation detected user '{user}' involved in {len(events)} high-risk security events " \
                     f"with {len(unique_ips)} different malicious IP addresses within 8 hours. " \
                     f"Threat IPs: {', '.join(unique_ips)}. " \
                     f"Event types: {', '.join(event_types)}. " \
                     f"Maximum risk score: {max_risk:.1f}."
        
        return {
            'title': title,
            'description': description,
            'severity': severity,
            'risk_score': round(max_risk, 1),
            'source_events': events,
            'correlation_type': 'user_anomaly',
            'threat_indicators': {'compromised_user': user, 'threat_ips': unique_ips}
        }
    
    def create_mitre_incident(self, chain_key, events, techniques, avg_risk):
        """Create incident for MITRE technique patterns"""
        hostname, source_ip = chain_key.split('_')
        tactics = list(set(e.mitre_tactic for e in events if e.mitre_tactic))
        
        severity = 'critical' if avg_risk >= 8.0 and len(techniques) >= 3 else 'high'
        
        title = f"Multi-Stage Attack Chain Detected on {hostname}"
        description = f"Automated correlation detected coordinated attack using {len(techniques)} MITRE ATT&CK techniques " \
                     f"from threat IP {source_ip} targeting {hostname}. " \
                     f"Techniques: {', '.join(techniques)}. " \
                     f"Tactics: {', '.join(tactics)}. " \
                     f"Average risk: {avg_risk:.1f}. " \
                     f"Timeline: {len(events)} events over 12 hours."
        
        return {
            'title': title,
            'description': description,
            'severity': severity,
            'risk_score': round(avg_risk, 1),
            'source_events': events,
            'correlation_type': 'mitre_pattern',
            'threat_indicators': {'attack_chain': techniques, 'target_host': hostname, 'source_ip': source_ip}
        }
    
    def save_incidents_to_database(self, incidents):
        """Save correlated incidents to database"""
        if not incidents:
            print("No incidents found through automated correlation")
            return 0
        
        # Clear existing incidents first
        existing_count = self.session.query(Incident).count()
        if existing_count > 0:
            print(f"Clearing {existing_count} existing incidents...")
            self.session.query(Incident).delete()
            self.session.commit()
        
        saved_count = 0
        current_time = datetime.utcnow()
        
        for i, incident_data in enumerate(incidents):
            incident_id = f"AUTO-{datetime.now().strftime('%Y%m%d')}-{(i+1):03d}"
            
            # Calculate when the incident was "detected" (earliest event time + 5 minutes)
            earliest_event = min(incident_data['source_events'], key=lambda e: e.timestamp)
            detection_time = earliest_event.timestamp + timedelta(minutes=5)
            
            incident = Incident(
                incident_id=incident_id,
                title=incident_data['title'],
                description=incident_data['description'],
                severity=incident_data['severity'],
                status='open',
                created_timestamp=detection_time,
                updated_timestamp=current_time,
                risk_score=incident_data['risk_score'],
                source_events_count=len(incident_data['source_events']),
                affected_systems=','.join(set(e.hostname for e in incident_data['source_events'] if e.hostname)),
                affected_users=','.join(set(e.user_id for e in incident_data['source_events'] if e.user_id)),
                mitre_techniques=','.join(set(e.mitre_technique for e in incident_data['source_events'] if e.mitre_technique))
            )
            
            self.session.add(incident)
            saved_count += 1
        
        self.session.commit()
        print(f"SUCCESS: Saved {saved_count} automatically correlated incidents")
        return saved_count
    
    def run_correlation(self):
        """Run all correlation algorithms"""
        print("AUTOMATED INCIDENT CORRELATION ENGINE")
        print("=" * 42)
        print("Analyzing real threat intelligence events for incident patterns...")
        print()
        
        all_incidents = []
        
        # Run different correlation algorithms
        ip_incidents = self.find_ip_based_incidents()
        user_incidents = self.find_user_based_incidents()  
        mitre_incidents = self.find_mitre_pattern_incidents()
        
        all_incidents.extend(ip_incidents)
        all_incidents.extend(user_incidents)
        all_incidents.extend(mitre_incidents)
        
        print(f"\nCORRELATION RESULTS:")
        print(f"- IP-based incidents: {len(ip_incidents)}")
        print(f"- User-based incidents: {len(user_incidents)}")
        print(f"- MITRE pattern incidents: {len(mitre_incidents)}")
        print(f"- Total incidents: {len(all_incidents)}")
        
        # Save to database
        if all_incidents:
            saved_count = self.save_incidents_to_database(all_incidents)
            
            print("\n" + "=" * 42)
            print("AUTOMATED CORRELATION COMPLETE!")
            print(f"Generated {saved_count} incidents purely from API threat intelligence")
            print("No manual templates used - 100% algorithmic correlation")
            
            # Show sample incidents
            print(f"\nSAMPLE AUTOMATED INCIDENTS:")
            for i, incident in enumerate(all_incidents[:3]):
                print(f"{i+1}. {incident['title']}")
                print(f"   Severity: {incident['severity']} | Risk: {incident['risk_score']} | Events: {len(incident['source_events'])}")
        else:
            print("\nNo correlatable incident patterns found in current data")
            print("This is normal - correlation requires multiple related events")
    
    def close(self):
        """Close database session"""
        self.session.close()

def main():
    """Run automated incident correlation"""
    correlator = AutomatedIncidentCorrelator()
    
    try:
        correlator.run_correlation()
    finally:
        correlator.close()

if __name__ == "__main__":
    main()