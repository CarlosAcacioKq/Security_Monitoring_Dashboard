#!/usr/bin/env python3
import logging
import argparse
import schedule
import time
import json
from typing import Dict
from datetime import datetime
from config.config import Config
from src.database.database import db_manager
from src.collectors.collector_manager import CollectorManager
from src.detection.detection_rules import DetectionEngine
from src.analytics.behavioral_analytics import BehavioralAnalytics
from src.analytics.incident_correlator import IncidentCorrelator
from src.alerting.notification_manager import NotificationManager
from src.compliance.compliance_monitor import ComplianceMonitor
from src.dashboard.report_generator import SecurityReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_monitor.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class SecurityMonitoringSystem:
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.collector_manager = None
        self.detection_engine = None
        self.behavioral_analytics = None
        self.incident_correlator = None
        self.notification_manager = None
        self.compliance_monitor = None
        self.report_generator = None
        
        self._initialize_components()
    
    def _load_config(self, config_file: str) -> Dict:
        if config_file:
            import yaml
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Default configuration
            return {
                'collectors': {
                    'windows_events': {
                        'enabled': True,
                        'collection_interval': 60
                    },
                    'syslog': {
                        'enabled': False,
                        'log_paths': ['/var/log/auth.log', '/var/log/secure']
                    },
                    'network_devices': {
                        'enabled': False,
                        'devices': []
                    }
                },
                'detection': {
                    'enabled': True,
                    'real_time': True
                },
                'analytics': {
                    'baseline_update_interval': 86400,  # 24 hours
                    'anomaly_detection': True
                },
                'alerting': {
                    'email_enabled': True,
                    'summary_reports': True,
                    'summary_interval': 86400  # 24 hours
                },
                'compliance': {
                    'frameworks': ['PCI-DSS', 'SOX'],
                    'evaluation_interval': 3600  # 1 hour
                }
            }
    
    def _initialize_components(self):
        try:
            # Initialize database
            db_manager.create_tables()
            
            # Initialize core components
            self.collector_manager = CollectorManager(self.config)
            self.detection_engine = DetectionEngine()
            self.behavioral_analytics = BehavioralAnalytics()
            self.incident_correlator = IncidentCorrelator()
            self.notification_manager = NotificationManager()
            self.compliance_monitor = ComplianceMonitor()
            self.report_generator = SecurityReportGenerator()
            
            logger.info("Security monitoring system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize system: {e}")
            raise
    
    def start_monitoring(self):
        try:
            # Start data collection
            if self.config.get('collectors', {}).get('enabled', True):
                self.collector_manager.start_collection()
            
            # Schedule baseline updates
            if self.config.get('analytics', {}).get('baseline_update_interval'):
                schedule.every().day.at("02:00").do(
                    self.behavioral_analytics.update_all_baselines
                )
            
            # Schedule compliance evaluations
            if self.config.get('compliance', {}).get('evaluation_interval'):
                schedule.every().hour.do(self._run_compliance_checks)
            
            # Schedule summary reports
            if self.config.get('alerting', {}).get('summary_reports'):
                schedule.every().day.at("08:00").do(
                    self.notification_manager.send_summary_report
                )
            
            logger.info("Security monitoring started")
            
            # Main monitoring loop
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            raise
    
    def stop_monitoring(self):
        try:
            if self.collector_manager:
                self.collector_manager.stop_collection()
            
            schedule.clear()
            db_manager.close_connection()
            
            logger.info("Security monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
    
    def _run_compliance_checks(self):
        try:
            frameworks = self.config.get('compliance', {}).get('frameworks', [])
            
            for framework in frameworks:
                result = self.compliance_monitor.evaluate_compliance(framework)
                logger.info(f"Compliance check completed for {framework}: {result['compliance_score']:.1f}%")
                
        except Exception as e:
            logger.error(f"Error in compliance checks: {e}")
    
    def run_initial_setup(self):
        logger.info("Running initial system setup...")
        
        # Create database tables
        db_manager.create_tables()
        
        # Run initial data collection
        total_events = self.collector_manager.collect_once()
        logger.info(f"Initial collection completed: {total_events} events")
        
        # Build initial baselines for existing users
        self.behavioral_analytics.update_all_baselines()
        
        # Run initial compliance check
        self._run_compliance_checks()
        
        logger.info("Initial setup completed successfully")

def main():
    parser = argparse.ArgumentParser(description='Security Monitoring Dashboard')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--setup', action='store_true', help='Run initial setup')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--collect-once', action='store_true', help='Run single collection cycle')
    parser.add_argument('--generate-report', help='Generate report (executive_summary, threat_trends, user_risk, compliance)')
    parser.add_argument('--compliance-check', help='Run compliance check for framework (PCI-DSS, SOX)')
    
    args = parser.parse_args()
    
    try:
        system = SecurityMonitoringSystem(args.config)
        
        if args.setup:
            system.run_initial_setup()
        elif args.collect_once:
            total_events = system.collector_manager.collect_once()
            print(f"Collected {total_events} events")
        elif args.generate_report:
            report = getattr(system.report_generator, f"generate_{args.generate_report}")()
            print(json.dumps(report, indent=2, default=str))
        elif args.compliance_check:
            result = system.compliance_monitor.evaluate_compliance(args.compliance_check)
            print(json.dumps(result, indent=2, default=str))
        elif args.daemon:
            system.start_monitoring()
        else:
            parser.print_help()
            
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())