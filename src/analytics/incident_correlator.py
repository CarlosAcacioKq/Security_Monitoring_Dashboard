from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from src.database.models import SecurityEvent, Incident, IncidentEvent
from src.database.database import db_manager
import logging
import uuid

logger = logging.getLogger(__name__)

class IncidentCorrelator:
    def __init__(self):
        self.correlation_window_minutes = 30
        self.min_events_for_incident = 3
        self.risk_score_threshold = 5.0
        
    def correlate_events(self, trigger_event: SecurityEvent) -> Optional[Dict]:
        session = db_manager.get_session()
        try:
            # Find related events within correlation window
            related_events = self._find_related_events(trigger_event, session)
            
            if len(related_events) < self.min_events_for_incident:
                return None
            
            # Calculate aggregate risk score
            total_risk_score = sum(event.risk_score for event in related_events)
            
            if total_risk_score < self.risk_score_threshold:
                return None
            
            # Create or update incident
            incident = self._create_or_update_incident(related_events, session)
            
            return {
                'incident_id': incident.incident_id,
                'total_risk_score': total_risk_score,
                'event_count': len(related_events),
                'correlation_type': self._determine_correlation_type(related_events)
            }
            
        finally:
            session.close()
    
    def _find_related_events(self, trigger_event: SecurityEvent, session: Session) -> List[SecurityEvent]:
        correlation_start = trigger_event.timestamp - timedelta(minutes=self.correlation_window_minutes)
        correlation_end = trigger_event.timestamp + timedelta(minutes=self.correlation_window_minutes)
        
        # Multiple correlation strategies
        related_events = set()
        
        # Strategy 1: Same user correlation
        if trigger_event.user_id:
            user_events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.user_id == trigger_event.user_id,
                    SecurityEvent.timestamp >= correlation_start,
                    SecurityEvent.timestamp <= correlation_end,
                    SecurityEvent.risk_score > 0
                )
            ).all()
            related_events.update(user_events)
        
        # Strategy 2: Same source IP correlation
        if trigger_event.source_ip:
            ip_events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.source_ip == trigger_event.source_ip,
                    SecurityEvent.timestamp >= correlation_start,
                    SecurityEvent.timestamp <= correlation_end,
                    SecurityEvent.risk_score > 0
                )
            ).all()
            related_events.update(ip_events)
        
        # Strategy 3: Same hostname correlation
        if trigger_event.hostname:
            host_events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.hostname == trigger_event.hostname,
                    SecurityEvent.timestamp >= correlation_start,
                    SecurityEvent.timestamp <= correlation_end,
                    SecurityEvent.risk_score > 0
                )
            ).all()
            related_events.update(host_events)
        
        # Strategy 4: MITRE technique correlation
        if trigger_event.mitre_technique:
            technique_events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.mitre_technique == trigger_event.mitre_technique,
                    SecurityEvent.timestamp >= correlation_start,
                    SecurityEvent.timestamp <= correlation_end,
                    SecurityEvent.risk_score > 0
                )
            ).all()
            related_events.update(technique_events)
        
        return list(related_events)
    
    def _determine_correlation_type(self, events: List[SecurityEvent]) -> str:
        correlation_factors = []
        
        # Check correlation factors
        users = set(event.user_id for event in events if event.user_id)
        if len(users) == 1:
            correlation_factors.append("user")
        
        source_ips = set(event.source_ip for event in events if event.source_ip)
        if len(source_ips) == 1:
            correlation_factors.append("source_ip")
        
        hostnames = set(event.hostname for event in events if event.hostname)
        if len(hostnames) == 1:
            correlation_factors.append("hostname")
        
        techniques = set(event.mitre_technique for event in events if event.mitre_technique)
        if len(techniques) == 1:
            correlation_factors.append("mitre_technique")
        
        return "_".join(correlation_factors) if correlation_factors else "temporal"
    
    def _create_or_update_incident(self, events: List[SecurityEvent], session: Session) -> Incident:
        # Check if any events are already part of an existing incident
        existing_incident = None
        for event in events:
            incident_event = session.query(IncidentEvent).filter(
                IncidentEvent.security_event_id == event.id
            ).first()
            
            if incident_event:
                existing_incident = incident_event.incident
                break
        
        if existing_incident:
            # Update existing incident
            incident = existing_incident
            incident.updated_timestamp = datetime.utcnow()
            incident.source_events_count = len(events)
            incident.risk_score = sum(event.risk_score for event in events)
        else:
            # Create new incident
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
            
            incident = Incident(
                incident_id=incident_id,
                title=self._generate_incident_title(events),
                description=self._generate_incident_description(events),
                severity=self._calculate_incident_severity(events),
                status='open',
                created_timestamp=datetime.utcnow(),
                updated_timestamp=datetime.utcnow(),
                source_events_count=len(events),
                risk_score=sum(event.risk_score for event in events),
                mitre_techniques=self._extract_mitre_techniques(events),
                affected_users=self._extract_affected_users(events),
                affected_systems=self._extract_affected_systems(events)
            )
            
            session.add(incident)
            session.flush()  # Get the incident ID
        
        # Link events to incident
        for event in events:
            # Check if event is already linked
            existing_link = session.query(IncidentEvent).filter(
                and_(
                    IncidentEvent.incident_id == incident.id,
                    IncidentEvent.security_event_id == event.id
                )
            ).first()
            
            if not existing_link:
                incident_event = IncidentEvent(
                    incident_id=incident.id,
                    security_event_id=event.id,
                    correlation_type=self._determine_correlation_type(events),
                    added_timestamp=datetime.utcnow()
                )
                session.add(incident_event)
        
        session.commit()
        return incident
    
    def _generate_incident_title(self, events: List[SecurityEvent]) -> str:
        # Analyze events to create descriptive title
        techniques = set(event.mitre_technique for event in events if event.mitre_technique)
        users = set(event.user_id for event in events if event.user_id)
        source_ips = set(event.source_ip for event in events if event.source_ip)
        
        if techniques:
            primary_technique = list(techniques)[0]
            if len(users) == 1:
                return f"Suspicious Activity - {primary_technique} - User: {list(users)[0]}"
            elif len(source_ips) == 1:
                return f"Suspicious Activity - {primary_technique} - IP: {list(source_ips)[0]}"
            else:
                return f"Suspicious Activity - {primary_technique}"
        else:
            return f"Correlated Security Events - {len(events)} events"
    
    def _generate_incident_description(self, events: List[SecurityEvent]) -> str:
        event_types = [event.event_type for event in events]
        unique_types = list(set(event_types))
        
        description = f"Incident created from {len(events)} correlated security events.\n"
        description += f"Event types: {', '.join(unique_types)}\n"
        description += f"Time range: {min(event.timestamp for event in events)} - {max(event.timestamp for event in events)}\n"
        
        return description
    
    def _calculate_incident_severity(self, events: List[SecurityEvent]) -> str:
        max_risk_score = max(event.risk_score for event in events)
        
        if max_risk_score >= 8.0:
            return 'critical'
        elif max_risk_score >= 6.0:
            return 'high'
        elif max_risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _extract_mitre_techniques(self, events: List[SecurityEvent]) -> str:
        techniques = set(event.mitre_technique for event in events if event.mitre_technique)
        return ', '.join(techniques)
    
    def _extract_affected_users(self, events: List[SecurityEvent]) -> str:
        users = set(event.user_id for event in events if event.user_id)
        return ', '.join(users)
    
    def _extract_affected_systems(self, events: List[SecurityEvent]) -> str:
        systems = set(event.hostname for event in events if event.hostname)
        return ', '.join(systems)