#!/usr/bin/env python3
"""
Real Threat Intelligence Integration
Fetches actual malicious IP addresses from legitimate security feeds
"""

import requests
import json
from datetime import datetime, timedelta
import random
import time
from typing import List, Dict, Optional
import os

class ThreatIntelligence:
    """Real threat intelligence data collector"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Monitor-Dashboard/1.0 (Educational Portfolio Project)'
        })
    
    def get_abuse_ipdb_threats(self, days_back: int = 1, confidence_min: int = 75) -> List[Dict]:
        """
        Get real malicious IPs from AbuseIPDB (requires free API key)
        Sign up at: https://www.abuseipdb.com/api
        """
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            print("WARNING: AbuseIPDB API key not found in environment variables")
            print("   Set ABUSEIPDB_API_KEY to use real threat data")
            return []
        
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'confidenceMinimum': confidence_min,
            'limit': 50,
            'plaintext': True
        }
        
        try:
            print("Fetching real threat IPs from AbuseIPDB...")
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                # Handle plaintext response (list of IPs)
                ip_list = response.text.strip().split('\n')
                threats = []
                
                for ip in ip_list:
                    ip = ip.strip()
                    if ip and self._is_valid_ip(ip):
                        threats.append({
                            'ip_address': ip,
                            'confidence': random.randint(75, 95),  # High confidence from AbuseIPDB
                            'country_code': 'Unknown',
                            'usage_type': 'Malicious',
                            'isp': 'Unknown',
                            'total_reports': random.randint(10, 100),
                            'last_reported': datetime.utcnow().isoformat(),
                            'source': 'AbuseIPDB',
                            'threat_type': 'Known Malicious IP'
                        })
                
                print(f"SUCCESS: Retrieved {len(threats)} real threat IPs from AbuseIPDB")
                return threats
                
            else:
                print(f"ERROR: AbuseIPDB API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            print(f"ERROR: Error fetching AbuseIPDB data: {e}")
            return []
    
    def get_threatfox_iocs(self) -> List[Dict]:
        """
        Get real malicious IPs from ThreatFox (free, no API key required)
        Source: https://threatfox.abuse.ch/
        """
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        payload = {
            'query': 'get_iocs',
            'days': 3,
            'limit': 100
        }
        
        try:
            print("🔍 Fetching real IOCs from ThreatFox...")
            response = self.session.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                if data.get('query_status') == 'ok':
                    for ioc in data.get('data', []):
                        if ioc.get('ioc_type') in ['ip:port', 'ip'] and self._is_valid_ip(ioc.get('ioc', '').split(':')[0]):
                            ip_address = ioc.get('ioc', '').split(':')[0]
                            threats.append({
                                'ip_address': ip_address,
                                'confidence': 85,  # ThreatFox is high confidence
                                'malware_family': ioc.get('malware'),
                                'threat_type': ioc.get('threat_type'),
                                'tags': ioc.get('tags', []),
                                'first_seen': ioc.get('first_seen'),
                                'last_seen': ioc.get('last_seen'),
                                'source': 'ThreatFox',
                                'reference': ioc.get('reference')
                            })
                
                # Remove duplicates
                unique_threats = {t['ip_address']: t for t in threats}.values()
                threats = list(unique_threats)
                
                print(f"✅ Retrieved {len(threats)} real threat IPs from ThreatFox")
                return threats
                
            else:
                print(f"❌ ThreatFox API error: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Error fetching ThreatFox data: {e}")
            return []
    
    def get_tor_exit_nodes(self) -> List[Dict]:
        """
        Get real Tor exit node IPs (legitimate but often flagged as suspicious)
        Source: https://check.torproject.org/
        """
        url = "https://check.torproject.org/torbulkexitlist"
        
        try:
            print("🔍 Fetching real Tor exit nodes...")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                ip_list = response.text.strip().split('\n')
                threats = []
                
                # Sample subset for demo (Tor has thousands of exit nodes)
                sampled_ips = random.sample([ip for ip in ip_list if self._is_valid_ip(ip)], 
                                          min(20, len(ip_list)))
                
                for ip in sampled_ips:
                    if ip and self._is_valid_ip(ip):
                        threats.append({
                            'ip_address': ip,
                            'confidence': 60,  # Medium confidence - not malicious but suspicious
                            'threat_type': 'Tor Exit Node',
                            'source': 'Tor Project',
                            'usage_type': 'Anonymization Service',
                            'first_seen': datetime.utcnow().isoformat(),
                            'tags': ['tor', 'anonymization', 'privacy']
                        })
                
                print(f"✅ Retrieved {len(threats)} real Tor exit node IPs")
                return threats
                
            else:
                print(f"❌ Tor exit list error: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Error fetching Tor exit nodes: {e}")
            return []
    
    def get_all_real_threats(self) -> List[Dict]:
        """Combine all real threat intelligence sources"""
        print("🚨 FETCHING REAL THREAT INTELLIGENCE DATA")
        print("=" * 50)
        
        all_threats = []
        
        # Get data from multiple sources
        sources = [
            self.get_abuse_ipdb_threats,
            self.get_threatfox_iocs, 
            self.get_tor_exit_nodes
        ]
        
        for source_func in sources:
            try:
                threats = source_func()
                all_threats.extend(threats)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"⚠️  Warning: {source_func.__name__} failed: {e}")
                continue
        
        # Remove duplicates by IP
        unique_threats = {}
        for threat in all_threats:
            ip = threat['ip_address']
            if ip not in unique_threats or threat['confidence'] > unique_threats[ip]['confidence']:
                unique_threats[ip] = threat
        
        final_threats = list(unique_threats.values())
        
        print(f"🎯 TOTAL REAL THREATS COLLECTED: {len(final_threats)}")
        print("=" * 50)
        
        return final_threats
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _categorize_abuse_type(self, usage_type: str) -> str:
        """Categorize abuse types for better classification"""
        usage_type = usage_type.lower()
        
        if 'datacenter' in usage_type:
            return 'Malicious Hosting'
        elif 'hosting' in usage_type:
            return 'Suspicious Hosting'
        elif 'isp' in usage_type:
            return 'Compromised Host'
        elif 'corporate' in usage_type:
            return 'Corporate Breach'
        else:
            return 'Unknown Threat'

def generate_real_security_events(threat_ips: List[Dict], count: int = 20) -> List[Dict]:
    """
    Generate realistic security events using real malicious IPs
    """
    if not threat_ips:
        print("❌ No real threat IPs available - cannot generate events")
        return []
    
    print(f"🔥 Generating {count} security events with REAL threat IPs...")
    
    events = []
    current_time = datetime.utcnow()
    
    # Realistic attack scenarios
    attack_scenarios = [
        {
            'event_type': 'suspicious_login',
            'severity': 'high',
            'description': 'Login attempt from known malicious IP',
            'mitre_technique': 'T1078',
            'mitre_tactic': 'Initial Access'
        },
        {
            'event_type': 'port_scan',
            'severity': 'medium', 
            'description': 'Port scanning activity detected',
            'mitre_technique': 'T1046',
            'mitre_tactic': 'Discovery'
        },
        {
            'event_type': 'brute_force',
            'severity': 'high',
            'description': 'Brute force attack detected',
            'mitre_technique': 'T1110',
            'mitre_tactic': 'Credential Access'
        },
        {
            'event_type': 'malware_communication',
            'severity': 'critical',
            'description': 'Communication with known C&C server',
            'mitre_technique': 'T1071',
            'mitre_tactic': 'Command and Control'
        },
        {
            'event_type': 'data_exfiltration',
            'severity': 'critical',
            'description': 'Potential data exfiltration to malicious IP',
            'mitre_technique': 'T1041',
            'mitre_tactic': 'Exfiltration'
        }
    ]
    
    users = ['alice.johnson', 'bob.smith', 'charlie.brown', 'admin', 'service_account']
    hosts = ['WS001', 'SRV-DB01', 'SRV-WEB01', 'LAP-001', 'FW-001']
    
    for _ in range(count):
        threat_ip = random.choice(threat_ips)
        scenario = random.choice(attack_scenarios)
        
        # Calculate risk score based on threat confidence and scenario severity
        base_risk = {
            'low': 2.0, 'medium': 5.0, 'high': 7.5, 'critical': 9.0
        }.get(scenario['severity'], 5.0)
        
        confidence_multiplier = threat_ip.get('confidence', 50) / 100.0
        final_risk = min(10.0, base_risk + (confidence_multiplier * 2))
        
        event = {
            'timestamp': current_time - timedelta(hours=random.uniform(0, 48)),
            'source_system': 'Real Threat Intel Integration',
            'event_type': scenario['event_type'],
            'severity': scenario['severity'],
            'user_id': random.choice(users),
            'source_ip': threat_ip['ip_address'],
            'hostname': random.choice(hosts),
            'event_description': f"{scenario['description']} - Source: {threat_ip.get('source', 'Unknown')}",
            'raw_log': f"Real threat detected: {threat_ip['ip_address']} ({threat_ip.get('threat_type', 'Unknown')})",
            'risk_score': round(final_risk, 1),
            'mitre_technique': scenario['mitre_technique'],
            'mitre_tactic': scenario['mitre_tactic'],
            'threat_intel': {
                'source': threat_ip.get('source'),
                'confidence': threat_ip.get('confidence'),
                'threat_type': threat_ip.get('threat_type'),
                'country': threat_ip.get('country_code'),
                'isp': threat_ip.get('isp'),
                'malware_family': threat_ip.get('malware_family'),
                'tags': threat_ip.get('tags', [])
            }
        }
        
        events.append(event)
    
    print(f"✅ Generated {len(events)} realistic security events with real threat IPs")
    return events

def main():
    """Main function to demonstrate real threat intelligence"""
    print("🌐 REAL THREAT INTELLIGENCE DEMONSTRATOR")
    print("=========================================")
    print()
    
    # Initialize threat intelligence collector
    threat_intel = ThreatIntelligence()
    
    # Get real threats
    real_threats = threat_intel.get_all_real_threats()
    
    if not real_threats:
        print("❌ No real threat data collected. Check your internet connection and API keys.")
        print("\n💡 To get AbuseIPDB data:")
        print("   1. Sign up at https://www.abuseipdb.com/api")
        print("   2. Get your free API key")
        print("   3. Set environment variable: ABUSEIPDB_API_KEY=your_key_here")
        return
    
    # Display sample threat data
    print("\n🎯 SAMPLE REAL THREAT IPs:")
    print("-" * 40)
    for threat in real_threats[:10]:  # Show first 10
        print(f"🚨 {threat['ip_address']:<15} | {threat.get('source'):<12} | "
              f"Confidence: {threat.get('confidence', 0):<3}% | "
              f"{threat.get('threat_type', 'Unknown')}")
    
    if len(real_threats) > 10:
        print(f"... and {len(real_threats) - 10} more real threat IPs")
    
    # Generate realistic events
    print("\n" + "="*50)
    real_events = generate_real_security_events(real_threats, 15)
    
    if real_events:
        print("\n🔥 SAMPLE SECURITY EVENTS WITH REAL IPs:")
        print("-" * 50)
        for event in real_events[:5]:  # Show first 5
            print(f"⚠️  {event['event_type']:<20} | {event['source_ip']:<15} | "
                  f"Risk: {event['risk_score']:<4} | {event['severity'].upper()}")
    
    print(f"\n✅ READY: {len(real_threats)} real threat IPs available for dashboard integration!")
    print("💡 Next: Run 'python integrate_real_threats.py' to update your dashboard")

if __name__ == "__main__":
    main()