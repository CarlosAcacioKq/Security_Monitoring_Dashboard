#!/usr/bin/env python3
"""
Integrate Real Threat Intelligence into Dashboard
Replaces demo data with actual malicious IP addresses from threat feeds
"""

from datetime import datetime, timedelta
import random
from real_threat_intel import ThreatIntelligence, generate_real_security_events
from src.database.database import db_manager
from src.database.models import SecurityEvent, Incident

def clear_demo_data():
    """Remove old demo data"""
    print("🗑️  Clearing old demo data...")
    session = db_manager.get_session()
    
    try:
        # Delete old demo events and incidents
        demo_events = session.query(SecurityEvent).filter(
            SecurityEvent.source_system.in_([
                'Demo Generator', 
                'Enhanced Demo Generator',
                'Live Simulation'
            ])
        ).delete(synchronize_session=False)
        
        demo_incidents = session.query(Incident).filter(
            Incident.title.like('%Demo%')
        ).delete(synchronize_session=False)
        
        session.commit()
        print(f"✅ Cleared {demo_events} demo events and {demo_incidents} demo incidents")
        
    except Exception as e:
        session.rollback()
        print(f"❌ Error clearing demo data: {e}")
    finally:
        session.close()

def integrate_real_threats():
    """Integrate real threat intelligence into the dashboard"""
    print("🌐 INTEGRATING REAL THREAT INTELLIGENCE")
    print("=" * 45)
    
    # Initialize threat intelligence
    threat_intel = ThreatIntelligence()
    
    # Get real threat data
    print("\n📡 Step 1: Fetching real threat intelligence...")
    real_threats = threat_intel.get_all_real_threats()
    
    if not real_threats:
        print("❌ No real threat data available. Dashboard will use existing data.")
        print("\n💡 To enable real threat feeds:")
        print("   • Get free API key from https://www.abuseipdb.com/api")
        print("   • Set environment variable: ABUSEIPDB_API_KEY=your_key")
        print("   • Ensure internet connectivity for public threat feeds")
        return False
    
    print(f"✅ Collected {len(real_threats)} real threat IPs from multiple sources")
    
    # Clear old demo data (optional - user choice)
    response = input("\n🤔 Clear existing demo data? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        clear_demo_data()
    
    # Generate realistic events with real IPs
    print("\n🔥 Step 2: Generating security events with real threat IPs...")
    real_events = generate_real_security_events(real_threats, count=50)
    
    if not real_events:
        print("❌ Failed to generate events with real threat data")
        return False
    
    # Insert into database
    print(f"\n💾 Step 3: Inserting {len(real_events)} events into database...")
    session = db_manager.get_session()
    
    try:
        events_added = 0
        for event_data in real_events:
            event = SecurityEvent(
                timestamp=event_data['timestamp'],
                source_system=event_data['source_system'],
                event_type=event_data['event_type'],
                severity=event_data['severity'],
                user_id=event_data['user_id'],
                source_ip=event_data['source_ip'],
                hostname=event_data['hostname'],
                event_description=event_data['event_description'],
                raw_log=event_data['raw_log'],
                risk_score=event_data['risk_score'],
                mitre_technique=event_data['mitre_technique'],
                mitre_tactic=event_data['mitre_tactic']
            )
            
            session.add(event)
            events_added += 1
        
        session.commit()
        print(f"✅ Successfully added {events_added} security events with real threat IPs")
        
        # Generate some incidents from high-risk events
        print("\n🚨 Step 4: Creating incidents from high-risk events...")
        incidents_created = create_incidents_from_threats(session, real_threats[:10])
        
        print(f"✅ Created {incidents_created} security incidents")
        
        # Display summary
        print("\n" + "=" * 45)
        print("🎯 REAL THREAT INTEGRATION COMPLETE!")
        print("=" * 45)
        print(f"• {len(real_threats)} real malicious IPs integrated")
        print(f"• {events_added} security events generated")
        print(f"• {incidents_created} incidents created")
        print("• Dashboard now shows REAL threat intelligence")
        print()
        print("🌐 Data sources:")
        sources = set(t.get('source', 'Unknown') for t in real_threats)
        for source in sources:
            count = sum(1 for t in real_threats if t.get('source') == source)
            print(f"  • {source}: {count} IPs")
        
        print("\n🚀 Next steps:")
        print("  1. Start dashboard: python web_dashboard.py")
        print("  2. View at: http://localhost:8050")
        print("  3. Check 'Threat Intelligence' tab for real IP analysis")
        
        return True
        
    except Exception as e:
        session.rollback()
        print(f"❌ Error inserting data: {e}")
        return False
    finally:
        session.close()

def create_incidents_from_threats(session, threat_ips, count=8):
    """Create realistic incidents using real threat intelligence"""
    
    incident_templates = [
        {
            'title': 'Brute Force Attack from Known Malicious IP',
            'description': 'Multiple failed login attempts detected from IP address in threat intelligence feeds',
            'severity': 'high',
            'category': 'brute_force'
        },
        {
            'title': 'Communication with Command & Control Server',
            'description': 'Outbound communication detected to known malware C&C infrastructure',
            'severity': 'critical',
            'category': 'malware_communication'
        },
        {
            'title': 'Tor Exit Node Activity',
            'description': 'Suspicious activity originating from Tor anonymization network',
            'severity': 'medium',
            'category': 'anonymization'
        },
        {
            'title': 'Data Exfiltration to Malicious Host',
            'description': 'Large data transfer detected to IP flagged as malicious hosting',
            'severity': 'critical',
            'category': 'data_exfiltration'
        }
    ]
    
    incidents_created = 0
    current_time = datetime.utcnow()
    
    for i in range(min(count, len(threat_ips))):
        threat = threat_ips[i]
        template = random.choice(incident_templates)
        
        # Calculate risk score based on threat confidence
        confidence = threat.get('confidence', 50)
        base_risk = {'low': 3, 'medium': 5, 'high': 7, 'critical': 9}.get(template['severity'], 5)
        risk_score = min(10.0, base_risk + (confidence / 100.0) * 2)
        
        incident = Incident(
            incident_id=f"REAL-{datetime.now().strftime('%Y%m%d')}-{i+1:03d}",
            title=f"{template['title']} ({threat['ip_address']})",
            description=f"{template['description']}. Source: {threat.get('source', 'Unknown')} (Confidence: {confidence}%)",
            severity=template['severity'],
            status='open' if random.random() > 0.3 else 'investigating',
            category=template['category'],
            created_timestamp=current_time - timedelta(hours=random.uniform(1, 72)),
            updated_timestamp=current_time - timedelta(minutes=random.uniform(15, 120)),
            risk_score=round(risk_score, 1),
            affected_systems=f"Multiple systems communicating with {threat['ip_address']}",
            source_events=f"Events involving real threat IP: {threat['ip_address']}",
            mitre_techniques=['T1078', 'T1110', 'T1071'] if template['category'] == 'brute_force' else ['T1041', 'T1071']
        )
        
        session.add(incident)
        incidents_created += 1
    
    session.commit()
    return incidents_created

def show_threat_summary():
    """Display current threat intelligence summary"""
    print("📊 CURRENT THREAT INTELLIGENCE SUMMARY")
    print("=" * 40)
    
    session = db_manager.get_session()
    
    try:
        # Count events by source system
        real_events = session.query(SecurityEvent).filter(
            SecurityEvent.source_system == 'Real Threat Intel Integration'
        ).count()
        
        # Count high-risk events
        high_risk = session.query(SecurityEvent).filter(
            SecurityEvent.source_system == 'Real Threat Intel Integration',
            SecurityEvent.risk_score >= 7.0
        ).count()
        
        # Count unique IPs
        from sqlalchemy import func
        unique_ips = session.query(func.count(func.distinct(SecurityEvent.source_ip))).filter(
            SecurityEvent.source_system == 'Real Threat Intel Integration'
        ).scalar()
        
        print(f"🔥 Real threat events: {real_events}")
        print(f"⚠️  High-risk events: {high_risk}")
        print(f"🌐 Unique malicious IPs: {unique_ips}")
        
        # Show recent high-risk IPs
        recent_threats = session.query(SecurityEvent.source_ip, SecurityEvent.risk_score).filter(
            SecurityEvent.source_system == 'Real Threat Intel Integration',
            SecurityEvent.risk_score >= 7.0
        ).distinct().limit(10).all()
        
        if recent_threats:
            print(f"\n🎯 Sample high-risk IPs:")
            for ip, risk in recent_threats:
                print(f"   {ip} (Risk: {risk})")
    
    except Exception as e:
        print(f"❌ Error getting summary: {e}")
    finally:
        session.close()

def main():
    """Main integration function"""
    print("REAL THREAT INTELLIGENCE INTEGRATION")
    print("=" * 50)
    
    # Check if database is ready
    try:
        db_manager.create_tables()
        print("✅ Database connection established")
    except Exception as e:
        print(f"❌ Database error: {e}")
        return
    
    # Show current status
    show_threat_summary()
    
    print("\n" + "=" * 50)
    print("🎯 INTEGRATION OPTIONS:")
    print("1. Integrate new real threat intelligence")
    print("2. Show current threat summary") 
    print("3. Exit")
    
    while True:
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            success = integrate_real_threats()
            if success:
                print("\nIntegration complete! Your dashboard now uses real threat data.")
                break
        elif choice == '2':
            show_threat_summary()
        elif choice == '3':
            print("Exiting without changes")
            break
        else:
            print("Invalid choice. Please select 1-3.")

if __name__ == "__main__":
    main()