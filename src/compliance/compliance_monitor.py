from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from src.database.models import SecurityEvent, ComplianceEvent, UserBaseline
from src.database.database import db_manager
import logging
import json

logger = logging.getLogger(__name__)

class ComplianceFramework:
    def __init__(self, name: str, controls: Dict[str, Dict]):
        self.name = name
        self.controls = controls
    
    def evaluate_control(self, control_id: str, events: List[SecurityEvent]) -> Dict:
        if control_id not in self.controls:
            raise ValueError(f"Unknown control: {control_id}")
        
        control_config = self.controls[control_id]
        evaluation_method = control_config.get('evaluation_method')
        
        if evaluation_method == 'event_count_threshold':
            return self._evaluate_by_event_count(control_config, events)
        elif evaluation_method == 'time_based_check':
            return self._evaluate_by_time_check(control_config, events)
        elif evaluation_method == 'user_behavior_check':
            return self._evaluate_by_user_behavior(control_config, events)
        else:
            return {'status': 'unknown', 'details': 'Unknown evaluation method'}
    
    def _evaluate_by_event_count(self, control_config: Dict, events: List[SecurityEvent]) -> Dict:
        event_types = control_config.get('monitored_event_types', [])
        threshold = control_config.get('threshold', 0)
        
        relevant_events = [e for e in events if e.event_type in event_types]
        count = len(relevant_events)
        
        if count <= threshold:
            return {
                'status': 'pass',
                'details': f"Event count {count} within threshold {threshold}",
                'evidence_count': count
            }
        else:
            return {
                'status': 'fail',
                'details': f"Event count {count} exceeds threshold {threshold}",
                'evidence_count': count,
                'violation_events': [e.id for e in relevant_events[:10]]
            }
    
    def _evaluate_by_time_check(self, control_config: Dict, events: List[SecurityEvent]) -> Dict:
        allowed_hours = control_config.get('allowed_hours', [])
        event_types = control_config.get('monitored_event_types', [])
        
        violations = []
        for event in events:
            if event.event_type in event_types:
                event_hour = event.timestamp.hour
                if event_hour not in allowed_hours:
                    violations.append(event)
        
        if not violations:
            return {
                'status': 'pass',
                'details': 'All access within allowed hours'
            }
        else:
            return {
                'status': 'fail',
                'details': f"{len(violations)} access attempts outside allowed hours",
                'violation_count': len(violations),
                'violation_events': [e.id for e in violations[:10]]
            }
    
    def _evaluate_by_user_behavior(self, control_config: Dict, events: List[SecurityEvent]) -> Dict:
        # Check for anomalous user behavior based on baselines
        session = db_manager.get_session()
        try:
            violations = []
            
            user_events = {}
            for event in events:
                if event.user_id:
                    if event.user_id not in user_events:
                        user_events[event.user_id] = []
                    user_events[event.user_id].append(event)
            
            for user_id, user_event_list in user_events.items():
                baseline = session.query(UserBaseline).filter(
                    UserBaseline.user_id == user_id
                ).first()
                
                if baseline:
                    # Check against baseline patterns
                    daily_count = len(user_event_list)
                    if daily_count > baseline.average_daily_logins * 2:
                        violations.extend(user_event_list)
            
            if not violations:
                return {
                    'status': 'pass',
                    'details': 'User behavior within normal patterns'
                }
            else:
                return {
                    'status': 'fail',
                    'details': f"Anomalous behavior detected for {len(set(e.user_id for e in violations))} users",
                    'violation_count': len(violations)
                }
                
        finally:
            session.close()

class PCIDSSCompliance(ComplianceFramework):
    def __init__(self):
        controls = {
            'PCI_8.1': {
                'name': 'Unique User IDs',
                'description': 'Assign unique IDs to each person with computer access',
                'evaluation_method': 'user_behavior_check',
                'monitored_event_types': ['auth_success', 'windows_logon']
            },
            'PCI_8.2': {
                'name': 'Strong Authentication',
                'description': 'Implement strong authentication for system access',
                'evaluation_method': 'event_count_threshold',
                'monitored_event_types': ['auth_failure', 'weak_auth_detected'],
                'threshold': 5
            },
            'PCI_10.1': {
                'name': 'Audit Trail Creation',
                'description': 'Implement audit trails to link access to individuals',
                'evaluation_method': 'event_count_threshold',
                'monitored_event_types': ['audit_failure', 'log_tampering'],
                'threshold': 0
            },
            'PCI_10.6': {
                'name': 'Daily Log Review',
                'description': 'Daily review of security events and audit logs',
                'evaluation_method': 'time_based_check',
                'monitored_event_types': ['privileged_access', 'admin_login'],
                'allowed_hours': list(range(8, 18))  # 8 AM to 6 PM
            }
        }
        super().__init__('PCI-DSS', controls)

class SOXCompliance(ComplianceFramework):
    def __init__(self):
        controls = {
            'SOX_302': {
                'name': 'Management Assessment',
                'description': 'Management assessment of internal controls',
                'evaluation_method': 'event_count_threshold',
                'monitored_event_types': ['unauthorized_access', 'privilege_escalation'],
                'threshold': 0
            },
            'SOX_404': {
                'name': 'Internal Control Assessment',
                'description': 'Annual internal control over financial reporting assessment',
                'evaluation_method': 'time_based_check',
                'monitored_event_types': ['financial_system_access'],
                'allowed_hours': list(range(6, 22))  # 6 AM to 10 PM
            }
        }
        super().__init__('SOX', controls)

class ComplianceMonitor:
    def __init__(self):
        self.frameworks = {
            'PCI-DSS': PCIDSSCompliance(),
            'SOX': SOXCompliance()
        }
        
    def evaluate_compliance(self, framework_name: str, period_days: int = 1) -> Dict:
        if framework_name not in self.frameworks:
            raise ValueError(f"Unknown compliance framework: {framework_name}")
        
        framework = self.frameworks[framework_name]
        
        # Get events for the evaluation period
        session = db_manager.get_session()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=period_days)
            
            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_date
            ).all()
            
            results = {}
            
            for control_id, control_config in framework.controls.items():
                try:
                    evaluation = framework.evaluate_control(control_id, events)
                    results[control_id] = {
                        'control_name': control_config['name'],
                        'description': control_config['description'],
                        'evaluation': evaluation,
                        'evaluated_at': datetime.utcnow()
                    }
                    
                    # Store compliance event
                    self._store_compliance_event(
                        framework_name, control_id, evaluation, session
                    )
                    
                except Exception as e:
                    logger.error(f"Error evaluating control {control_id}: {e}")
                    results[control_id] = {
                        'control_name': control_config['name'],
                        'evaluation': {'status': 'error', 'details': str(e)},
                        'evaluated_at': datetime.utcnow()
                    }
            
            session.commit()
            
            # Calculate overall compliance score
            passed_controls = len([r for r in results.values() if r['evaluation']['status'] == 'pass'])
            total_controls = len(results)
            compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
            
            return {
                'framework': framework_name,
                'evaluation_period_days': period_days,
                'compliance_score': compliance_score,
                'total_controls': total_controls,
                'passed_controls': passed_controls,
                'failed_controls': total_controls - passed_controls,
                'control_results': results,
                'evaluated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def _store_compliance_event(self, framework: str, control_id: str, evaluation: Dict, session: Session):
        try:
            compliance_event = ComplianceEvent(
                timestamp=datetime.utcnow(),
                compliance_framework=framework,
                control_id=control_id,
                event_type='control_evaluation',
                status=evaluation['status'],
                details=evaluation['details'],
                evidence_path=json.dumps(evaluation.get('violation_events', []))
            )
            
            session.add(compliance_event)
            
        except Exception as e:
            logger.error(f"Error storing compliance event: {e}")
    
    def generate_compliance_report(self, framework_name: str, period_days: int = 30) -> Dict:
        session = db_manager.get_session()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=period_days)
            
            # Get compliance events for the period
            compliance_events = session.query(ComplianceEvent).filter(
                and_(
                    ComplianceEvent.compliance_framework == framework_name,
                    ComplianceEvent.timestamp >= start_date
                )
            ).all()
            
            # Aggregate by control
            control_summary = {}
            for event in compliance_events:
                control_id = event.control_id
                if control_id not in control_summary:
                    control_summary[control_id] = {
                        'pass_count': 0,
                        'fail_count': 0,
                        'warning_count': 0,
                        'latest_status': event.status,
                        'latest_evaluation': event.timestamp
                    }
                
                control_summary[control_id][f"{event.status}_count"] += 1
                
                # Update latest status if this event is newer
                if event.timestamp > control_summary[control_id]['latest_evaluation']:
                    control_summary[control_id]['latest_status'] = event.status
                    control_summary[control_id]['latest_evaluation'] = event.timestamp
            
            # Calculate overall compliance score
            passing_controls = len([c for c in control_summary.values() if c['latest_status'] == 'pass'])
            total_controls = len(control_summary)
            compliance_score = (passing_controls / total_controls * 100) if total_controls > 0 else 0
            
            return {
                'framework': framework_name,
                'report_period_days': period_days,
                'compliance_score': compliance_score,
                'total_controls_evaluated': total_controls,
                'passing_controls': passing_controls,
                'failing_controls': total_controls - passing_controls,
                'control_summary': control_summary,
                'total_evaluations': len(compliance_events),
                'report_generated_at': datetime.utcnow().isoformat()
            }
            
        finally:
            session.close()
    
    def get_compliance_violations(self, framework_name: str, days: int = 7) -> List[Dict]:
        session = db_manager.get_session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            violations = session.query(ComplianceEvent).filter(
                and_(
                    ComplianceEvent.compliance_framework == framework_name,
                    ComplianceEvent.status == 'fail',
                    ComplianceEvent.timestamp >= cutoff_date
                )
            ).order_by(ComplianceEvent.timestamp.desc()).all()
            
            return [
                {
                    'control_id': v.control_id,
                    'timestamp': v.timestamp.isoformat(),
                    'details': v.details,
                    'user_id': v.user_id,
                    'system_id': v.system_id,
                    'evidence_path': v.evidence_path
                } for v in violations
            ]
            
        finally:
            session.close()