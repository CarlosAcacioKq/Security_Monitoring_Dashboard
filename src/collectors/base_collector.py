from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class BaseCollector(ABC):
    def __init__(self, name: str, config: Dict):
        self.name = name
        self.config = config
        self.is_running = False
        
    @abstractmethod
    def collect(self) -> List[Dict]:
        pass
    
    def normalize_event(self, raw_event: Dict) -> Dict:
        normalized = {
            'timestamp': self._extract_timestamp(raw_event),
            'source_system': self.name,
            'event_type': self._extract_event_type(raw_event),
            'severity': self._extract_severity(raw_event),
            'user_id': self._extract_user_id(raw_event),
            'source_ip': self._extract_source_ip(raw_event),
            'destination_ip': self._extract_destination_ip(raw_event),
            'hostname': self._extract_hostname(raw_event),
            'process_name': self._extract_process_name(raw_event),
            'command_line': self._extract_command_line(raw_event),
            'file_path': self._extract_file_path(raw_event),
            'event_description': self._extract_description(raw_event),
            'raw_log': str(raw_event),
            'risk_score': 0.0
        }
        return {k: v for k, v in normalized.items() if v is not None}
    
    def _extract_timestamp(self, event: Dict) -> datetime:
        timestamp_fields = ['timestamp', 'time', 'datetime', '@timestamp', 'event_time']
        for field in timestamp_fields:
            if field in event:
                try:
                    if isinstance(event[field], datetime):
                        return event[field]
                    return datetime.fromisoformat(str(event[field]).replace('Z', '+00:00'))
                except:
                    continue
        return datetime.utcnow()
    
    def _extract_event_type(self, event: Dict) -> Optional[str]:
        type_fields = ['event_type', 'type', 'event_id', 'log_name']
        for field in type_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_severity(self, event: Dict) -> str:
        severity_fields = ['severity', 'level', 'priority']
        for field in severity_fields:
            if field in event:
                severity = str(event[field]).lower()
                if severity in ['critical', 'high', 'error']:
                    return 'high'
                elif severity in ['warning', 'warn', 'medium']:
                    return 'medium'
                elif severity in ['info', 'information', 'low']:
                    return 'low'
        return 'medium'
    
    def _extract_user_id(self, event: Dict) -> Optional[str]:
        user_fields = ['user', 'username', 'user_id', 'account', 'subject_user_name']
        for field in user_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_source_ip(self, event: Dict) -> Optional[str]:
        ip_fields = ['source_ip', 'src_ip', 'client_ip', 'remote_ip', 'ip_address']
        for field in ip_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_destination_ip(self, event: Dict) -> Optional[str]:
        dest_fields = ['destination_ip', 'dest_ip', 'target_ip', 'server_ip']
        for field in dest_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_hostname(self, event: Dict) -> Optional[str]:
        host_fields = ['hostname', 'computer', 'host', 'machine_name', 'computer_name']
        for field in host_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_process_name(self, event: Dict) -> Optional[str]:
        process_fields = ['process_name', 'process', 'executable', 'image']
        for field in process_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_command_line(self, event: Dict) -> Optional[str]:
        cmd_fields = ['command_line', 'cmdline', 'command', 'process_command_line']
        for field in cmd_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_file_path(self, event: Dict) -> Optional[str]:
        file_fields = ['file_path', 'file', 'target_filename', 'object_name']
        for field in file_fields:
            if field in event and event[field]:
                return str(event[field])
        return None
    
    def _extract_description(self, event: Dict) -> Optional[str]:
        desc_fields = ['description', 'message', 'event_description', 'details']
        for field in desc_fields:
            if field in event and event[field]:
                return str(event[field])
        return None