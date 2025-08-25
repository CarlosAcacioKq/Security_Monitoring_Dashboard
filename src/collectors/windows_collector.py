import wmi
import json
from datetime import datetime
from typing import Dict, List
from .base_collector import BaseCollector
import logging

logger = logging.getLogger(__name__)

class WindowsEventCollector(BaseCollector):
    def __init__(self, config: Dict):
        super().__init__("Windows Event Log", config)
        self.wmi_connection = None
        self._initialize_wmi()
        
    def _initialize_wmi(self):
        try:
            self.wmi_connection = wmi.WMI()
            logger.info("WMI connection established")
        except Exception as e:
            logger.error(f"Failed to establish WMI connection: {e}")
            raise
    
    def collect(self) -> List[Dict]:
        events = []
        try:
            # Collect Security Events (Event ID 4624 - Successful Logon)
            security_events = self.wmi_connection.query(
                "SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'Security' AND EventCode = 4624"
            )
            
            for event in security_events:
                normalized_event = self._parse_security_event(event)
                events.append(self.normalize_event(normalized_event))
            
            # Collect System Events
            system_events = self.wmi_connection.query(
                "SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'System' AND Type = 'Error'"
            )
            
            for event in system_events:
                normalized_event = self._parse_system_event(event)
                events.append(self.normalize_event(normalized_event))
                
            logger.info(f"Collected {len(events)} Windows events")
            
        except Exception as e:
            logger.error(f"Error collecting Windows events: {e}")
            
        return events
    
    def _parse_security_event(self, event) -> Dict:
        return {
            'timestamp': self._convert_wmi_time(event.TimeGenerated),
            'event_type': 'windows_logon',
            'event_id': event.EventCode,
            'severity': 'low',
            'hostname': event.ComputerName,
            'user': self._extract_user_from_message(event.Message),
            'event_description': event.Message,
            'source_name': event.SourceName,
            'record_number': event.RecordNumber
        }
    
    def _parse_system_event(self, event) -> Dict:
        return {
            'timestamp': self._convert_wmi_time(event.TimeGenerated),
            'event_type': 'windows_system_error',
            'event_id': event.EventCode,
            'severity': 'high',
            'hostname': event.ComputerName,
            'event_description': event.Message,
            'source_name': event.SourceName,
            'record_number': event.RecordNumber
        }
    
    def _convert_wmi_time(self, wmi_time) -> datetime:
        if wmi_time:
            try:
                return datetime.strptime(wmi_time.split('.')[0], '%Y%m%d%H%M%S')
            except:
                pass
        return datetime.utcnow()
    
    def _extract_user_from_message(self, message: str) -> str:
        if message and 'Account Name:' in message:
            lines = message.split('\n')
            for line in lines:
                if 'Account Name:' in line:
                    return line.split('Account Name:')[1].strip()
        return None