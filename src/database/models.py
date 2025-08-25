from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class SecurityEvent(Base):
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    source_system = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    user_id = Column(String(100))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    hostname = Column(String(255))
    process_name = Column(String(255))
    command_line = Column(Text)
    file_path = Column(Text)
    event_description = Column(Text)
    raw_log = Column(Text)
    risk_score = Column(Float, default=0.0)
    mitre_technique = Column(String(20))
    mitre_tactic = Column(String(50))
    is_false_positive = Column(Boolean, default=False)
    investigated_by = Column(String(100))
    investigation_notes = Column(Text)
    
    __table_args__ = (
        Index('idx_timestamp', 'timestamp'),
        Index('idx_source_system', 'source_system'),
        Index('idx_event_type', 'event_type'),
        Index('idx_user_id', 'user_id'),
        Index('idx_source_ip', 'source_ip'),
        Index('idx_risk_score', 'risk_score'),
        Index('idx_mitre_technique', 'mitre_technique'),
    )

class UserBaseline(Base):
    __tablename__ = 'user_baselines'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False)
    baseline_start_date = Column(DateTime, nullable=False)
    baseline_end_date = Column(DateTime, nullable=False)
    typical_login_hours_start = Column(Integer)
    typical_login_hours_end = Column(Integer)
    common_source_ips = Column(Text)
    common_hostnames = Column(Text)
    average_daily_logins = Column(Integer)
    common_applications = Column(Text)
    geographic_locations = Column(Text)
    privilege_level = Column(String(50))
    department = Column(String(100))
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_user_id', 'user_id'),
        Index('idx_last_updated', 'last_updated'),
    )

class Incident(Base):
    __tablename__ = 'incidents'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default='open')
    created_timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_timestamp = Column(DateTime, default=datetime.utcnow)
    assigned_to = Column(String(100))
    source_events_count = Column(Integer, default=0)
    risk_score = Column(Float, nullable=False)
    mitre_techniques = Column(Text)
    affected_users = Column(Text)
    affected_systems = Column(Text)
    resolution_notes = Column(Text)
    
    events = relationship("IncidentEvent", back_populates="incident")
    
    __table_args__ = (
        Index('idx_incident_id', 'incident_id'),
        Index('idx_created_timestamp', 'created_timestamp'),
        Index('idx_severity', 'severity'),
        Index('idx_status', 'status'),
        Index('idx_risk_score', 'risk_score'),
    )

class IncidentEvent(Base):
    __tablename__ = 'incident_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey('incidents.id'), nullable=False)
    security_event_id = Column(Integer, ForeignKey('security_events.id'), nullable=False)
    correlation_type = Column(String(100))
    added_timestamp = Column(DateTime, default=datetime.utcnow)
    
    incident = relationship("Incident", back_populates="events")
    security_event = relationship("SecurityEvent")

class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(String(500), nullable=False)
    threat_type = Column(String(100))
    confidence_score = Column(Float)
    source = Column(String(100), nullable=False)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime)
    is_active = Column(Boolean, default=True)
    description = Column(Text)
    mitre_techniques = Column(Text)
    
    __table_args__ = (
        Index('idx_ioc_value', 'ioc_value'),
        Index('idx_ioc_type', 'ioc_type'),
        Index('idx_threat_type', 'threat_type'),
        Index('idx_is_active', 'is_active'),
    )

class ComplianceEvent(Base):
    __tablename__ = 'compliance_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    compliance_framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False)
    user_id = Column(String(100))
    system_id = Column(String(100))
    details = Column(Text)
    evidence_path = Column(String(500))
    auditor_notes = Column(Text)
    
    __table_args__ = (
        Index('idx_compliance_timestamp', 'timestamp'),
        Index('idx_compliance_framework', 'compliance_framework'),
        Index('idx_control_id', 'control_id'),
        Index('idx_compliance_status', 'status'),
    )