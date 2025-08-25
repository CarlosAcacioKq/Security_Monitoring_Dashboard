import re
import os
from datetime import datetime
from typing import Dict, List
from .base_collector import BaseCollector
import logging

logger = logging.getLogger(__name__)

class SyslogCollector(BaseCollector):
    def __init__(self, config: Dict):
        super().__init__("Linux Syslog", config)
        self.log_paths = config.get('log_paths', ['/var/log/auth.log', '/var/log/secure'])
        self.last_position = {}
        
    def collect(self) -> List[Dict]:
        events = []
        
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                try:
                    new_events = self._read_new_lines(log_path)
                    events.extend(new_events)
                except Exception as e:
                    logger.error(f"Error reading {log_path}: {e}")
        
        logger.info(f"Collected {len(events)} syslog events")
        return events
    
    def _read_new_lines(self, log_path: str) -> List[Dict]:
        events = []
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get current position
                current_pos = self.last_position.get(log_path, 0)
                f.seek(current_pos)
                
                for line in f:
                    line = line.strip()
                    if line:
                        parsed_event = self._parse_syslog_line(line)
                        if parsed_event:
                            events.append(self.normalize_event(parsed_event))
                
                # Update position
                self.last_position[log_path] = f.tell()
                
        except Exception as e:
            logger.error(f"Error reading {log_path}: {e}")
            
        return events
    
    def _parse_syslog_line(self, line: str) -> Dict:
        # Standard syslog format: timestamp hostname process[pid]: message
        syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.+)$'
        
        match = re.match(syslog_pattern, line)
        if not match:
            return {
                'timestamp': datetime.utcnow(),
                'event_type': 'syslog_unparsed',
                'severity': 'low',
                'raw_message': line
            }
        
        timestamp_str, hostname, process, pid, message = match.groups()
        
        # Parse timestamp (assuming current year)
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except:
            timestamp = datetime.utcnow()
        
        event = {
            'timestamp': timestamp,
            'hostname': hostname,
            'process_name': process,
            'process_id': pid,
            'message': message,
            'raw_message': line
        }
        
        # Determine event type and severity based on content
        event_type, severity = self._classify_syslog_event(process, message)
        event['event_type'] = event_type
        event['severity'] = severity
        
        # Extract user information for auth events
        if 'ssh' in process.lower() or 'login' in process.lower():
            user = self._extract_user_from_auth_message(message)
            if user:
                event['user'] = user
        
        return event
    
    def _classify_syslog_event(self, process: str, message: str) -> tuple:
        process_lower = process.lower()
        message_lower = message.lower()
        
        # Authentication events
        if any(keyword in process_lower for keyword in ['ssh', 'login', 'su', 'sudo']):
            if any(keyword in message_lower for keyword in ['failed', 'failure', 'invalid', 'denied']):
                return 'auth_failure', 'medium'
            elif any(keyword in message_lower for keyword in ['accepted', 'successful', 'opened']):
                return 'auth_success', 'low'
            else:
                return 'auth_other', 'low'
        
        # System events
        elif process_lower in ['kernel', 'systemd']:
            if any(keyword in message_lower for keyword in ['error', 'critical', 'failed']):
                return 'system_error', 'high'
            else:
                return 'system_info', 'low'
        
        # Security-related processes
        elif any(keyword in process_lower for keyword in ['security', 'audit', 'firewall']):
            return 'security_event', 'medium'
        
        # Default classification
        else:
            if any(keyword in message_lower for keyword in ['error', 'critical', 'failed']):
                return 'general_error', 'medium'
            else:
                return 'general_info', 'low'
    
    def _extract_user_from_auth_message(self, message: str) -> str:
        # Common patterns for extracting usernames from auth messages
        patterns = [
            r'user (\w+)',
            r'for (\w+) from',
            r'for user (\w+)',
            r'session opened for user (\w+)',
            r'authentication failure.*user=(\w+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None