import re
import json
from datetime import datetime
from typing import Dict, List
from .base_collector import BaseCollector
import logging

logger = logging.getLogger(__name__)

class NetworkDeviceCollector(BaseCollector):
    def __init__(self, config: Dict):
        super().__init__("Network Device", config)
        self.device_configs = config.get('devices', [])
        
    def collect(self) -> List[Dict]:
        events = []
        
        for device_config in self.device_configs:
            try:
                device_events = self._collect_from_device(device_config)
                events.extend(device_events)
            except Exception as e:
                logger.error(f"Error collecting from device {device_config.get('name', 'unknown')}: {e}")
        
        logger.info(f"Collected {len(events)} network device events")
        return events
    
    def _collect_from_device(self, device_config: Dict) -> List[Dict]:
        device_type = device_config.get('type', 'generic')
        log_path = device_config.get('log_path')
        
        if not log_path or not os.path.exists(log_path):
            return []
        
        events = []
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed_event = self._parse_network_log(line, device_type, device_config)
                        if parsed_event:
                            events.append(self.normalize_event(parsed_event))
        except Exception as e:
            logger.error(f"Error reading network log {log_path}: {e}")
            
        return events
    
    def _parse_network_log(self, line: str, device_type: str, device_config: Dict) -> Dict:
        device_name = device_config.get('name', 'unknown_device')
        
        if device_type.lower() == 'cisco':
            return self._parse_cisco_log(line, device_name)
        elif device_type.lower() == 'juniper':
            return self._parse_juniper_log(line, device_name)
        elif device_type.lower() == 'palo_alto':
            return self._parse_palo_alto_log(line, device_name)
        else:
            return self._parse_generic_network_log(line, device_name)
    
    def _parse_cisco_log(self, line: str, device_name: str) -> Dict:
        # Cisco syslog format: timestamp: %facility-severity-mnemonic: description
        cisco_pattern = r'^(\S+\s+\d+\s+\d+:\d+:\d+(?:\.\d+)?)\s*:\s*%(\w+)-(\d+)-(\w+):\s*(.+)$'
        
        match = re.match(cisco_pattern, line)
        if not match:
            return self._parse_generic_network_log(line, device_name)
        
        timestamp_str, facility, severity_num, mnemonic, description = match.groups()
        
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except:
            timestamp = datetime.utcnow()
        
        severity = self._map_cisco_severity(int(severity_num))
        event_type = self._classify_cisco_event(facility, mnemonic, description)
        
        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'severity': severity,
            'hostname': device_name,
            'facility': facility,
            'mnemonic': mnemonic,
            'event_description': description,
            'raw_message': line,
            'source_ip': self._extract_ip_from_description(description, 'source'),
            'destination_ip': self._extract_ip_from_description(description, 'destination')
        }
    
    def _parse_palo_alto_log(self, line: str, device_name: str) -> Dict:
        # Palo Alto CSV format
        fields = line.split(',')
        if len(fields) < 10:
            return self._parse_generic_network_log(line, device_name)
        
        try:
            return {
                'timestamp': datetime.strptime(fields[1], "%Y/%m/%d %H:%M:%S"),
                'event_type': 'palo_alto_' + fields[3].lower(),
                'severity': self._map_palo_alto_action_to_severity(fields[4]),
                'hostname': device_name,
                'source_ip': fields[7],
                'destination_ip': fields[8],
                'source_port': fields[9],
                'destination_port': fields[10],
                'protocol': fields[6],
                'action': fields[4],
                'event_description': f"Traffic {fields[4]} from {fields[7]} to {fields[8]}",
                'raw_message': line
            }
        except:
            return self._parse_generic_network_log(line, device_name)
    
    def _parse_juniper_log(self, line: str, device_name: str) -> Dict:
        # Juniper format similar to standard syslog
        return self._parse_generic_network_log(line, device_name)
    
    def _parse_generic_network_log(self, line: str, device_name: str) -> Dict:
        return {
            'timestamp': datetime.utcnow(),
            'event_type': 'network_generic',
            'severity': 'low',
            'hostname': device_name,
            'event_description': line,
            'raw_message': line,
            'source_ip': self._extract_ip_from_description(line, 'source'),
            'destination_ip': self._extract_ip_from_description(line, 'destination')
        }
    
    def _map_cisco_severity(self, severity_num: int) -> str:
        severity_map = {
            0: 'high',    # Emergency
            1: 'high',    # Alert
            2: 'high',    # Critical
            3: 'high',    # Error
            4: 'medium',  # Warning
            5: 'low',     # Notice
            6: 'low',     # Informational
            7: 'low'      # Debug
        }
        return severity_map.get(severity_num, 'medium')
    
    def _map_palo_alto_action_to_severity(self, action: str) -> str:
        action_lower = action.lower()
        if action_lower in ['deny', 'drop', 'block']:
            return 'medium'
        elif action_lower in ['allow', 'permit']:
            return 'low'
        else:
            return 'medium'
    
    def _classify_cisco_event(self, facility: str, mnemonic: str, description: str) -> str:
        facility_lower = facility.lower()
        mnemonic_lower = mnemonic.lower()
        
        if facility_lower in ['sec', 'security']:
            return 'network_security'
        elif 'login' in mnemonic_lower or 'auth' in mnemonic_lower:
            return 'network_auth'
        elif 'link' in mnemonic_lower or 'interface' in mnemonic_lower:
            return 'network_interface'
        else:
            return 'network_general'
    
    def _extract_ip_from_description(self, text: str, ip_type: str) -> str:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        if ip_type == 'source' and len(ips) >= 1:
            return ips[0]
        elif ip_type == 'destination' and len(ips) >= 2:
            return ips[1]
        elif len(ips) >= 1:
            return ips[0]
        
        return None