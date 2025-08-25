#!/usr/bin/env python3
"""
Refresh Demo Data - Updates timestamps to current date
Keeps dashboard looking fresh and current for demos
"""

from datetime import datetime, timedelta
import random
from src.database.database import db_manager
from src.database.models import SecurityEvent, Incident, UserBaseline

def refresh_timestamps():
    """Update all timestamps to recent dates"""
    print("REFRESHING DEMO DATA TIMESTAMPS")
    print("=" * 40)
    
    session = db_manager.get_session()
    
    try:
        current_time = datetime.utcnow()
        
        # Update Security Events to last 7 days
        print("Updating security events...")
        events = session.query(SecurityEvent).all()
        for i, event in enumerate(events):
            # Spread events over last 7 days with more recent activity
            days_back = random.choices([0, 1, 2, 3, 4, 5, 6], weights=[30, 25, 20, 15, 5, 3, 2])[0]
            hours_back = random.randint(0, 23)
            minutes_back = random.randint(0, 59)
            
            new_timestamp = current_time - timedelta(days=days_back, hours=hours_back, minutes=minutes_back)
            event.timestamp = new_timestamp
            
            if i % 100 == 0:
                print(f"  Updated {i+1}/{len(events)} events")
        
        # Update Incidents to recent dates
        print("Updating incidents...")
        incidents = session.query(Incident).all()
        for incident in incidents:
            # Incidents in last 3 days
            days_back = random.uniform(0, 3)
            incident.created_timestamp = current_time - timedelta(days=days_back)
            incident.updated_timestamp = current_time - timedelta(hours=random.uniform(0, 24))
        
        # Update User Baselines
        print("Updating user baselines...")
        baselines = session.query(UserBaseline).all()
        for baseline in baselines:
            baseline.baseline_end_date = current_time
            baseline.baseline_start_date = current_time - timedelta(days=30)
            baseline.last_updated = current_time
        
        session.commit()
        
        print(f"SUCCESS: Refreshed {len(events)} events, {len(incidents)} incidents")
        print(f"Data now spans: {current_time - timedelta(days=7)} to {current_time}")
        print("Dashboard will show current, fresh data!")
        
    except Exception as e:
        session.rollback()
        print(f"Error refreshing data: {e}")
    finally:
        session.close()

def add_recent_high_risk_events(count=10):
    """Add some recent high-risk events for demo impact"""
    print(f"\\nAdding {count} recent high-risk events...")
    
    session = db_manager.get_session()
    
    try:
        current_time = datetime.utcnow()
        
        high_risk_scenarios = [
            {
                'event_type': 'privilege_escalation',
                'severity': 'critical',
                'risk_score': random.uniform(8.5, 10.0),
                'description': 'Critical privilege escalation attempt detected',
                'mitre_technique': 'T1068'
            },
            {
                'event_type': 'suspicious_activity',
                'severity': 'high', 
                'risk_score': random.uniform(7.0, 8.5),
                'description': 'Suspicious administrative activity detected',
                'mitre_technique': 'T1059'
            },
            {
                'event_type': 'auth_failure',
                'severity': 'high',
                'risk_score': random.uniform(6.5, 8.0),
                'description': 'Multiple authentication failures detected',
                'mitre_technique': 'T1110'
            }
        ]
        
        suspicious_ips = ['192.168.1.15', '192.168.1.25', '203.0.113.15', '10.0.0.99']
        users = ['alice.johnson', 'admin', 'bob.smith', 'service_account']
        hosts = ['WS001', 'SRV-DB01', 'LAP-001', 'SRV-WEB01']
        
        for _ in range(count):
            scenario = random.choice(high_risk_scenarios)
            
            event = SecurityEvent(
                timestamp=current_time - timedelta(minutes=random.randint(1, 120)),
                source_system='Enhanced Demo Generator',
                event_type=scenario['event_type'],
                severity=scenario['severity'],
                user_id=random.choice(users),
                source_ip=random.choice(suspicious_ips),
                hostname=random.choice(hosts),
                event_description=scenario['description'],
                raw_log=f"Demo event generated at {current_time}",
                risk_score=scenario['risk_score'],
                mitre_technique=scenario['mitre_technique'],
                mitre_tactic='Execution' if scenario['mitre_technique'] == 'T1059' else 'Privilege Escalation'
            )
            
            session.add(event)
        
        session.commit()
        print(f"Added {count} high-risk events in last 2 hours")
        
    except Exception as e:
        session.rollback()
        print(f"Error adding events: {e}")
    finally:
        session.close()

def main():
    print("DEMO DATA REFRESHER")
    print("Keeps your dashboard looking current and active")
    print()
    
    # Refresh all timestamps
    refresh_timestamps()
    
    # Add some recent activity
    add_recent_high_risk_events(15)
    
    print()
    print("COMPLETE! Your dashboard now shows:")
    print("- Current dates (last 7 days)")  
    print("- Recent high-risk activity")
    print("- Fresh incident timestamps")
    print("- Updated user baselines")
    print()
    print("Perfect for demos and screenshots!")

if __name__ == "__main__":
    main()