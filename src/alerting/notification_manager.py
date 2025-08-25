import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from datetime import datetime
from config.config import Config
from src.database.models import Incident, SecurityEvent
import logging
import json

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_user = Config.SMTP_USER
        self.smtp_password = Config.SMTP_PASSWORD
        
        # Notification rules configuration
        self.notification_rules = {
            'critical': {
                'email': True,
                'sms': True,
                'immediate': True,
                'recipients': ['security-team@company.com', 'soc-manager@company.com']
            },
            'high': {
                'email': True,
                'sms': False,
                'immediate': True,
                'recipients': ['security-team@company.com']
            },
            'medium': {
                'email': True,
                'sms': False,
                'immediate': False,
                'recipients': ['security-analysts@company.com']
            },
            'low': {
                'email': False,
                'sms': False,
                'immediate': False,
                'recipients': []
            }
        }
    
    def send_incident_alert(self, incident: Incident, events: List[SecurityEvent]):
        try:
            severity = incident.severity.lower()
            rules = self.notification_rules.get(severity, {})
            
            if not rules.get('email', False):
                logger.debug(f"No email notification configured for severity: {severity}")
                return
            
            recipients = rules.get('recipients', [])
            if not recipients:
                logger.warning(f"No recipients configured for severity: {severity}")
                return
            
            # Generate email content
            subject = f"[SECURITY ALERT - {severity.upper()}] {incident.title}"
            body = self._generate_incident_email_body(incident, events)
            
            # Send email
            self._send_email(recipients, subject, body)
            
            logger.info(f"Alert sent for incident {incident.incident_id} to {len(recipients)} recipients")
            
        except Exception as e:
            logger.error(f"Error sending incident alert: {e}")
    
    def send_detection_alert(self, detection: Dict, event: SecurityEvent):
        try:
            risk_score = detection.get('risk_score', 0)
            severity = self._risk_score_to_severity(risk_score)
            
            rules = self.notification_rules.get(severity, {})
            
            if not rules.get('immediate', False):
                logger.debug(f"No immediate notification for detection severity: {severity}")
                return
            
            recipients = rules.get('recipients', [])
            if not recipients:
                return
            
            subject = f"[DETECTION - {severity.upper()}] {detection.get('rule_name', 'Security Rule Triggered')}"
            body = self._generate_detection_email_body(detection, event)
            
            self._send_email(recipients, subject, body)
            
            logger.info(f"Detection alert sent for rule {detection.get('rule_triggered')}")
            
        except Exception as e:
            logger.error(f"Error sending detection alert: {e}")
    
    def _send_email(self, recipients: List[str], subject: str, body: str):
        if not all([self.smtp_server, self.smtp_user, self.smtp_password]):
            logger.warning("SMTP configuration incomplete - cannot send email")
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.debug(f"Email sent successfully to {recipients}")
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            raise
    
    def _generate_incident_email_body(self, incident: Incident, events: List[SecurityEvent]) -> str:
        body = f"""
        <html>
        <body>
            <h2>Security Incident Alert</h2>
            <p><strong>Incident ID:</strong> {incident.incident_id}</p>
            <p><strong>Title:</strong> {incident.title}</p>
            <p><strong>Severity:</strong> {incident.severity.upper()}</p>
            <p><strong>Risk Score:</strong> {incident.risk_score:.1f}/10.0</p>
            <p><strong>Created:</strong> {incident.created_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            
            <h3>Description</h3>
            <p>{incident.description}</p>
            
            <h3>MITRE ATT&CK Techniques</h3>
            <p>{incident.mitre_techniques or 'None identified'}</p>
            
            <h3>Affected Assets</h3>
            <p><strong>Users:</strong> {incident.affected_users or 'None'}</p>
            <p><strong>Systems:</strong> {incident.affected_systems or 'None'}</p>
            
            <h3>Related Events ({len(events)})</h3>
            <table border="1" style="border-collapse: collapse; width: 100%;">
                <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>User</th>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                </tr>
        """
        
        for event in events[:10]:  # Show first 10 events
            body += f"""
                <tr>
                    <td>{event.timestamp.strftime('%H:%M:%S')}</td>
                    <td>{event.event_type}</td>
                    <td>{event.user_id or 'N/A'}</td>
                    <td>{event.source_ip or 'N/A'}</td>
                    <td>{event.risk_score:.1f}</td>
                </tr>
            """
        
        if len(events) > 10:
            body += f"<tr><td colspan='5'><em>... and {len(events) - 10} more events</em></td></tr>"
        
        body += """
            </table>
            
            <p><strong>Action Required:</strong> Please investigate this incident immediately and update the status in the Security Dashboard.</p>
        </body>
        </html>
        """
        
        return body
    
    def _generate_detection_email_body(self, detection: Dict, event: SecurityEvent) -> str:
        body = f"""
        <html>
        <body>
            <h2>Security Detection Alert</h2>
            <p><strong>Rule:</strong> {detection.get('rule_name', 'Unknown')}</p>
            <p><strong>Risk Score:</strong> {detection.get('risk_score', 0):.1f}/10.0</p>
            <p><strong>MITRE Technique:</strong> {detection.get('mitre_technique', 'N/A')}</p>
            <p><strong>Timestamp:</strong> {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            
            <h3>Description</h3>
            <p>{detection.get('description', 'No description available')}</p>
            
            <h3>Event Details</h3>
            <p><strong>Event Type:</strong> {event.event_type}</p>
            <p><strong>User:</strong> {event.user_id or 'N/A'}</p>
            <p><strong>Source IP:</strong> {event.source_ip or 'N/A'}</p>
            <p><strong>Hostname:</strong> {event.hostname or 'N/A'}</p>
            <p><strong>Process:</strong> {event.process_name or 'N/A'}</p>
            
            <h3>Evidence</h3>
            <p>{detection.get('evidence', 'No evidence details available')}</p>
            
            <p><strong>Next Steps:</strong> Review this detection and determine if further investigation is required.</p>
        </body>
        </html>
        """
        
        return body
    
    def _risk_score_to_severity(self, risk_score: float) -> str:
        if risk_score >= 8.0:
            return 'critical'
        elif risk_score >= 6.0:
            return 'high'
        elif risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def send_summary_report(self, period_hours: int = 24):
        try:
            from src.database.database import db_manager
            session = db_manager.get_session()
            
            # Get incidents from the last period
            cutoff_time = datetime.utcnow() - timedelta(hours=period_hours)
            
            recent_incidents = session.query(Incident).filter(
                Incident.created_timestamp >= cutoff_time
            ).all()
            
            if not recent_incidents:
                logger.info("No incidents to report in summary")
                return
            
            subject = f"Security Summary Report - Last {period_hours} Hours"
            body = self._generate_summary_report_body(recent_incidents, period_hours)
            
            # Send to all configured recipients
            all_recipients = set()
            for severity_rules in self.notification_rules.values():
                all_recipients.update(severity_rules.get('recipients', []))
            
            if all_recipients:
                self._send_email(list(all_recipients), subject, body)
                logger.info(f"Summary report sent covering {len(recent_incidents)} incidents")
            
        except Exception as e:
            logger.error(f"Error sending summary report: {e}")
        finally:
            session.close()
    
    def _generate_summary_report_body(self, incidents: List[Incident], period_hours: int) -> str:
        severity_counts = {}
        for incident in incidents:
            severity_counts[incident.severity] = severity_counts.get(incident.severity, 0) + 1
        
        body = f"""
        <html>
        <body>
            <h2>Security Summary Report</h2>
            <p><strong>Period:</strong> Last {period_hours} hours</p>
            <p><strong>Total Incidents:</strong> {len(incidents)}</p>
            
            <h3>Incidents by Severity</h3>
            <ul>
                <li>Critical: {severity_counts.get('critical', 0)}</li>
                <li>High: {severity_counts.get('high', 0)}</li>
                <li>Medium: {severity_counts.get('medium', 0)}</li>
                <li>Low: {severity_counts.get('low', 0)}</li>
            </ul>
            
            <h3>Recent Incidents</h3>
            <table border="1" style="border-collapse: collapse; width: 100%;">
                <tr>
                    <th>Incident ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                    <th>Created</th>
                </tr>
        """
        
        for incident in incidents:
            body += f"""
                <tr>
                    <td>{incident.incident_id}</td>
                    <td>{incident.title}</td>
                    <td>{incident.severity.upper()}</td>
                    <td>{incident.risk_score:.1f}</td>
                    <td>{incident.status.upper()}</td>
                    <td>{incident.created_timestamp.strftime('%m/%d %H:%M')}</td>
                </tr>
            """
        
        body += """
            </table>
            
            <p>For detailed incident information, please access the Security Dashboard.</p>
        </body>
        </html>
        """
        
        return body