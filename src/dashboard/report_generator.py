import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc
from src.database.models import SecurityEvent, Incident, UserBaseline, ComplianceEvent
from src.database.database import db_manager
import json
import logging

logger = logging.getLogger(__name__)

class SecurityReportGenerator:
    def __init__(self):
        self.report_cache = {}
        
    def generate_executive_summary(self, days: int = 7) -> Dict:
        session = db_manager.get_session()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Incident statistics
            incidents = session.query(Incident).filter(
                Incident.created_timestamp >= start_date
            ).all()
            
            incident_stats = {
                'total_incidents': len(incidents),
                'critical_incidents': len([i for i in incidents if i.severity == 'critical']),
                'high_incidents': len([i for i in incidents if i.severity == 'high']),
                'medium_incidents': len([i for i in incidents if i.severity == 'medium']),
                'low_incidents': len([i for i in incidents if i.severity == 'low']),
                'open_incidents': len([i for i in incidents if i.status == 'open']),
                'resolved_incidents': len([i for i in incidents if i.status == 'resolved'])
            }
            
            # Event volume statistics
            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_date
            ).all()
            
            event_stats = {
                'total_events': len(events),
                'high_risk_events': len([e for e in events if e.risk_score >= 6.0]),
                'medium_risk_events': len([e for e in events if 3.0 <= e.risk_score < 6.0]),
                'low_risk_events': len([e for e in events if e.risk_score < 3.0]),
                'events_per_day': len(events) / days if days > 0 else 0
            }
            
            # Top threats
            top_mitre_techniques = session.query(
                SecurityEvent.mitre_technique, 
                func.count(SecurityEvent.id).label('count')
            ).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.mitre_technique.isnot(None)
                )
            ).group_by(SecurityEvent.mitre_technique).order_by(desc('count')).limit(5).all()
            
            # Top risk users
            top_risk_users = session.query(
                SecurityEvent.user_id,
                func.avg(SecurityEvent.risk_score).label('avg_risk'),
                func.count(SecurityEvent.id).label('event_count')
            ).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.user_id.isnot(None),
                    SecurityEvent.risk_score > 0
                )
            ).group_by(SecurityEvent.user_id).order_by(desc('avg_risk')).limit(10).all()
            
            return {
                'period': f"{days} days",
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d'),
                'incident_statistics': incident_stats,
                'event_statistics': event_stats,
                'top_mitre_techniques': [{'technique': t[0], 'count': t[1]} for t in top_mitre_techniques],
                'top_risk_users': [{'user': u[0], 'avg_risk': float(u[1]), 'events': u[2]} for u in top_risk_users],
                'generated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def generate_threat_trend_analysis(self, days: int = 30) -> Dict:
        session = db_manager.get_session()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Daily threat counts
            daily_threats = session.query(
                func.date(SecurityEvent.timestamp).label('date'),
                func.count(SecurityEvent.id).label('count'),
                func.avg(SecurityEvent.risk_score).label('avg_risk')
            ).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.risk_score > 0
                )
            ).group_by(func.date(SecurityEvent.timestamp)).order_by('date').all()
            
            # MITRE technique trends
            technique_trends = session.query(
                SecurityEvent.mitre_technique,
                func.date(SecurityEvent.timestamp).label('date'),
                func.count(SecurityEvent.id).label('count')
            ).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.mitre_technique.isnot(None)
                )
            ).group_by(SecurityEvent.mitre_technique, func.date(SecurityEvent.timestamp)).all()
            
            return {
                'period': f"{days} days",
                'daily_threats': [
                    {
                        'date': str(row[0]),
                        'count': row[1],
                        'avg_risk_score': float(row[2]) if row[2] else 0
                    } for row in daily_threats
                ],
                'technique_trends': [
                    {
                        'technique': row[0],
                        'date': str(row[1]),
                        'count': row[2]
                    } for row in technique_trends
                ],
                'generated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def generate_user_risk_report(self, top_n: int = 50) -> Dict:
        session = db_manager.get_session()
        try:
            # Calculate risk scores for all users in last 30 days
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            
            user_risk_data = session.query(
                SecurityEvent.user_id,
                func.count(SecurityEvent.id).label('total_events'),
                func.avg(SecurityEvent.risk_score).label('avg_risk_score'),
                func.max(SecurityEvent.risk_score).label('max_risk_score'),
                func.count(func.distinct(SecurityEvent.source_ip)).label('unique_ips'),
                func.count(func.distinct(SecurityEvent.hostname)).label('unique_hosts')
            ).filter(
                and_(
                    SecurityEvent.timestamp >= cutoff_date,
                    SecurityEvent.user_id.isnot(None)
                )
            ).group_by(SecurityEvent.user_id).order_by(desc('avg_risk_score')).limit(top_n).all()
            
            users = []
            for row in user_risk_data:
                user_id, total_events, avg_risk, max_risk, unique_ips, unique_hosts = row
                
                # Get user baseline information
                baseline = session.query(UserBaseline).filter(
                    UserBaseline.user_id == user_id
                ).first()
                
                users.append({
                    'user_id': user_id,
                    'total_events': total_events,
                    'avg_risk_score': float(avg_risk) if avg_risk else 0,
                    'max_risk_score': float(max_risk) if max_risk else 0,
                    'unique_ips': unique_ips,
                    'unique_hosts': unique_hosts,
                    'department': baseline.department if baseline else 'Unknown',
                    'privilege_level': baseline.privilege_level if baseline else 'Unknown'
                })
            
            return {
                'top_risk_users': users,
                'period_days': 30,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def generate_compliance_report(self, framework: str = 'PCI-DSS') -> Dict:
        session = db_manager.get_session()
        try:
            # Get compliance events for the specified framework
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            
            compliance_events = session.query(ComplianceEvent).filter(
                and_(
                    ComplianceEvent.compliance_framework == framework,
                    ComplianceEvent.timestamp >= cutoff_date
                )
            ).all()
            
            # Group by control ID and status
            control_status = {}
            for event in compliance_events:
                control_id = event.control_id
                if control_id not in control_status:
                    control_status[control_id] = {'pass': 0, 'fail': 0, 'warning': 0}
                
                control_status[control_id][event.status] = control_status[control_id].get(event.status, 0) + 1
            
            # Calculate compliance score
            total_controls = len(control_status)
            passing_controls = len([c for c in control_status.values() if c['pass'] > c['fail']])
            compliance_score = (passing_controls / total_controls * 100) if total_controls > 0 else 0
            
            return {
                'framework': framework,
                'compliance_score': compliance_score,
                'total_controls_evaluated': total_controls,
                'passing_controls': passing_controls,
                'failing_controls': total_controls - passing_controls,
                'control_details': control_status,
                'period_days': 30,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def export_to_csv(self, report_type: str, **kwargs) -> str:
        if report_type == 'executive_summary':
            data = self.generate_executive_summary(kwargs.get('days', 7))
        elif report_type == 'threat_trends':
            data = self.generate_threat_trend_analysis(kwargs.get('days', 30))
        elif report_type == 'user_risk':
            data = self.generate_user_risk_report(kwargs.get('top_n', 50))
        elif report_type == 'compliance':
            data = self.generate_compliance_report(kwargs.get('framework', 'PCI-DSS'))
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Convert to DataFrame and export
        if report_type == 'user_risk':
            df = pd.DataFrame(data['top_risk_users'])
        elif report_type == 'threat_trends':
            df = pd.DataFrame(data['daily_threats'])
        else:
            # For other reports, create a summary DataFrame
            df = pd.DataFrame([data])
        
        filename = f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = f"reports/{filename}"
        
        # Ensure reports directory exists
        import os
        os.makedirs('reports', exist_ok=True)
        
        df.to_csv(filepath, index=False)
        logger.info(f"Report exported to {filepath}")
        
        return filepath