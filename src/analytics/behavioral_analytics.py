import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from src.database.models import SecurityEvent, UserBaseline
from src.database.database import db_manager
import logging
import json

logger = logging.getLogger(__name__)

class BehavioralAnalytics:
    def __init__(self):
        self.baseline_window_days = 30
        self.anomaly_threshold = 2.0  # Standard deviations
        
    def build_user_baseline(self, user_id: str, end_date: Optional[datetime] = None) -> Dict:
        if not end_date:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=self.baseline_window_days)
        
        session = db_manager.get_session()
        try:
            # Get user's historical events
            events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.user_id == user_id,
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.timestamp <= end_date,
                    SecurityEvent.event_type.in_(['auth_success', 'windows_logon'])
                )
            ).all()
            
            if len(events) < 10:  # Need minimum data for baseline
                return None
            
            baseline = self._analyze_user_patterns(events)
            baseline['user_id'] = user_id
            baseline['baseline_start_date'] = start_date
            baseline['baseline_end_date'] = end_date
            baseline['last_updated'] = datetime.utcnow()
            
            # Store or update baseline in database
            self._store_user_baseline(baseline, session)
            
            return baseline
            
        finally:
            session.close()
    
    def _analyze_user_patterns(self, events: List[SecurityEvent]) -> Dict:
        df = pd.DataFrame([{
            'timestamp': event.timestamp,
            'hour': event.timestamp.hour,
            'weekday': event.timestamp.weekday(),
            'source_ip': event.source_ip,
            'hostname': event.hostname
        } for event in events])
        
        # Analyze login time patterns
        hourly_counts = df['hour'].value_counts().sort_index()
        peak_hours = hourly_counts[hourly_counts > hourly_counts.mean()].index.tolist()
        
        typical_start = min(peak_hours) if peak_hours else 9
        typical_end = max(peak_hours) if peak_hours else 17
        
        # Analyze IP patterns
        common_ips = df['source_ip'].value_counts().head(5).index.tolist()
        
        # Analyze hostname patterns
        common_hostnames = df['hostname'].value_counts().head(5).index.tolist()
        
        # Calculate daily login average
        daily_counts = df.groupby(df['timestamp'].dt.date).size()
        avg_daily_logins = int(daily_counts.mean())
        
        # Analyze geographic patterns (mock - would integrate with IP geolocation)
        geographic_locations = self._mock_geographic_analysis(common_ips)
        
        return {
            'typical_login_hours_start': typical_start,
            'typical_login_hours_end': typical_end,
            'common_source_ips': json.dumps(common_ips),
            'common_hostnames': json.dumps(common_hostnames),
            'average_daily_logins': avg_daily_logins,
            'geographic_locations': json.dumps(geographic_locations)
        }
    
    def _mock_geographic_analysis(self, ip_list: List[str]) -> List[Dict]:
        # Mock geographic data - in production, integrate with IP geolocation service
        locations = []
        for ip in ip_list[:3]:  # Top 3 IPs
            locations.append({
                'ip': ip,
                'country': 'US',  # Mock data
                'city': 'New York',
                'frequency': 1.0
            })
        return locations
    
    def _store_user_baseline(self, baseline: Dict, session: Session):
        try:
            # Check if baseline exists
            existing_baseline = session.query(UserBaseline).filter(
                UserBaseline.user_id == baseline['user_id']
            ).first()
            
            if existing_baseline:
                # Update existing baseline
                for key, value in baseline.items():
                    if hasattr(existing_baseline, key):
                        setattr(existing_baseline, key, value)
            else:
                # Create new baseline
                new_baseline = UserBaseline(**baseline)
                session.add(new_baseline)
            
            session.commit()
            logger.info(f"Baseline updated for user {baseline['user_id']}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error storing baseline for user {baseline['user_id']}: {e}")
    
    def detect_anomalies(self, event: SecurityEvent) -> List[Dict]:
        anomalies = []
        
        if not event.user_id:
            return anomalies
        
        session = db_manager.get_session()
        try:
            # Get user baseline
            baseline = session.query(UserBaseline).filter(
                UserBaseline.user_id == event.user_id
            ).first()
            
            if not baseline:
                # No baseline available - create one
                self.build_user_baseline(event.user_id)
                return anomalies
            
            # Check for time-based anomalies
            time_anomaly = self._check_time_anomaly(event, baseline)
            if time_anomaly:
                anomalies.append(time_anomaly)
            
            # Check for location-based anomalies
            location_anomaly = self._check_location_anomaly(event, baseline)
            if location_anomaly:
                anomalies.append(location_anomaly)
            
            # Check for frequency anomalies
            frequency_anomaly = self._check_frequency_anomaly(event, baseline, session)
            if frequency_anomaly:
                anomalies.append(frequency_anomaly)
            
        finally:
            session.close()
        
        return anomalies
    
    def _check_time_anomaly(self, event: SecurityEvent, baseline: UserBaseline) -> Optional[Dict]:
        event_hour = event.timestamp.hour
        
        # Check if outside typical hours
        if not (baseline.typical_login_hours_start <= event_hour <= baseline.typical_login_hours_end):
            severity = 'high' if event.timestamp.weekday() >= 5 else 'medium'  # Weekend vs weekday
            
            return {
                'anomaly_type': 'unusual_time',
                'description': f"Login outside typical hours ({baseline.typical_login_hours_start}-{baseline.typical_login_hours_end})",
                'risk_score': 5.0 if severity == 'medium' else 7.0,
                'event_time': event_hour,
                'baseline_start': baseline.typical_login_hours_start,
                'baseline_end': baseline.typical_login_hours_end
            }
        
        return None
    
    def _check_location_anomaly(self, event: SecurityEvent, baseline: UserBaseline) -> Optional[Dict]:
        if not event.source_ip:
            return None
        
        try:
            common_ips = json.loads(baseline.common_source_ips) if baseline.common_source_ips else []
            
            # Check if IP is in common IPs
            if event.source_ip not in common_ips:
                return {
                    'anomaly_type': 'unusual_location',
                    'description': f"Login from uncommon IP address: {event.source_ip}",
                    'risk_score': 6.0,
                    'source_ip': event.source_ip,
                    'common_ips': common_ips
                }
        except:
            pass
        
        return None
    
    def _check_frequency_anomaly(self, event: SecurityEvent, baseline: UserBaseline, session: Session) -> Optional[Dict]:
        # Check today's login count vs average
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        today_logins = session.query(SecurityEvent).filter(
            and_(
                SecurityEvent.user_id == event.user_id,
                SecurityEvent.timestamp >= today_start,
                SecurityEvent.timestamp < today_end,
                SecurityEvent.event_type.in_(['auth_success', 'windows_logon'])
            )
        ).count()
        
        if today_logins > (baseline.average_daily_logins * 3):  # More than 3x normal
            return {
                'anomaly_type': 'unusual_frequency',
                'description': f"Unusually high login frequency: {today_logins} vs average {baseline.average_daily_logins}",
                'risk_score': 4.5,
                'today_count': today_logins,
                'baseline_average': baseline.average_daily_logins
            }
        
        return None
    
    def update_all_baselines(self):
        session = db_manager.get_session()
        try:
            # Get all users who have had activity in the last 30 days
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            
            active_users = session.query(SecurityEvent.user_id).filter(
                and_(
                    SecurityEvent.timestamp >= cutoff_date,
                    SecurityEvent.user_id.isnot(None)
                )
            ).distinct().all()
            
            for (user_id,) in active_users:
                try:
                    self.build_user_baseline(user_id)
                    logger.info(f"Updated baseline for user {user_id}")
                except Exception as e:
                    logger.error(f"Error updating baseline for user {user_id}: {e}")
            
            logger.info(f"Baseline update completed for {len(active_users)} users")
            
        finally:
            session.close()