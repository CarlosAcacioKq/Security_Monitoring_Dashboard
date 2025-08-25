#!/usr/bin/env python3
"""
Simulate live security events for dashboard testing
Generates new events every few seconds to show real-time updates
"""

import time
import random
from datetime import datetime
from src.database.database import db_manager
from src.database.models import SecurityEvent

def generate_live_event():
    """Generate a single realistic security event"""
    
    # Random event types with different risk levels
    event_scenarios = [
        {
            'event_type': 'auth_failure',
            'severity': 'high',
            'risk_score': random.uniform(6.0, 8.0),
            'description': 'Failed authentication attempt detected',
            'source_ip': random.choice(['192.168.1.200', '203.0.113.100', '10.0.0.99']),
            'user_id': random.choice(['admin', 'user1', 'service_account'])
        },
        {
            'event_type': 'privilege_escalation', 
            'severity': 'critical',
            'risk_score': random.uniform(8.5, 10.0),
            'description': 'Potential privilege escalation detected',
            'source_ip': random.choice(['192.168.1.15', '192.168.1.25']),
            'user_id': random.choice(['alice.johnson', 'bob.smith'])
        },
        {
            'event_type': 'suspicious_activity',
            'severity': 'medium', 
            'risk_score': random.uniform(4.0, 6.0),
            'description': 'Suspicious activity detected',
            'source_ip': random.choice(['192.168.1.10', '172.16.1.10']),
            'user_id': random.choice(['charlie.brown', 'diana.ross'])
        }
    ]
    
    scenario = random.choice(event_scenarios)
    
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        source_system='Live Simulation',
        event_type=scenario['event_type'],
        severity=scenario['severity'],
        user_id=scenario['user_id'],
        source_ip=scenario['source_ip'],
        hostname=random.choice(['WS001', 'SRV-DB01', 'LAP-001']),
        event_description=scenario['description'],
        raw_log=f"Simulated event at {datetime.utcnow()}",
        risk_score=scenario['risk_score'],
        mitre_technique=random.choice(['T1078', 'T1110', 'T1059', None]),
        mitre_tactic=random.choice(['Initial Access', 'Credential Access', None])
    )
    
    return event

def main():
    print("LIVE EVENT SIMULATOR")
    print("===================")
    print("Generating new security events every 10 seconds...")
    print("Watch your dashboard at http://localhost:8050")
    print("Press Ctrl+C to stop")
    print()
    
    session = db_manager.get_session()
    event_count = 0
    
    try:
        while True:
            # Generate 1-3 events
            num_events = random.randint(1, 3)
            
            for _ in range(num_events):
                event = generate_live_event()
                session.add(event)
                event_count += 1
            
            session.commit()
            
            print(f"Generated {num_events} new events (Total: {event_count})")
            print(f"Latest: {event.event_type} from {event.source_ip} (Risk: {event.risk_score:.1f})")
            print("Dashboard should update in next refresh cycle...")
            print()
            
            # Wait 10 seconds
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("Stopping event simulation...")
    finally:
        session.close()
        print(f"Generated {event_count} total events")

if __name__ == "__main__":
    main()