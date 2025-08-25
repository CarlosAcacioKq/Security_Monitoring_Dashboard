import threading
import time
import schedule
from typing import Dict, List
from datetime import datetime
from .windows_collector import WindowsEventCollector
from .syslog_collector import SyslogCollector
from .network_collector import NetworkDeviceCollector
from src.database.database import db_manager
from src.database.models import SecurityEvent
import logging

logger = logging.getLogger(__name__)

class CollectorManager:
    def __init__(self, config: Dict):
        self.config = config
        self.collectors = []
        self.is_running = False
        self.collection_thread = None
        self._initialize_collectors()
        
    def _initialize_collectors(self):
        try:
            # Initialize Windows Event Collector
            if self.config.get('collectors', {}).get('windows_events', {}).get('enabled', False):
                windows_config = self.config['collectors']['windows_events']
                self.collectors.append(WindowsEventCollector(windows_config))
                logger.info("Windows Event Collector initialized")
            
            # Initialize Syslog Collector
            if self.config.get('collectors', {}).get('syslog', {}).get('enabled', False):
                syslog_config = self.config['collectors']['syslog']
                self.collectors.append(SyslogCollector(syslog_config))
                logger.info("Syslog Collector initialized")
            
            # Initialize Network Device Collector
            if self.config.get('collectors', {}).get('network_devices', {}).get('enabled', False):
                network_config = self.config['collectors']['network_devices']
                self.collectors.append(NetworkDeviceCollector(network_config))
                logger.info("Network Device Collector initialized")
                
            logger.info(f"Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            logger.error(f"Error initializing collectors: {e}")
            raise
    
    def start_collection(self):
        if self.is_running:
            logger.warning("Collection already running")
            return
        
        self.is_running = True
        
        # Schedule collection every minute
        schedule.every(1).minutes.do(self._collect_all_events)
        
        # Start scheduler in separate thread
        self.collection_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.collection_thread.start()
        
        logger.info("Collection started")
    
    def stop_collection(self):
        self.is_running = False
        schedule.clear()
        
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=5)
        
        logger.info("Collection stopped")
    
    def _run_scheduler(self):
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in scheduler: {e}")
                time.sleep(5)
    
    def _collect_all_events(self):
        total_events = 0
        
        for collector in self.collectors:
            try:
                events = collector.collect()
                if events:
                    self._store_events(events)
                    total_events += len(events)
                    logger.debug(f"{collector.name}: collected {len(events)} events")
            except Exception as e:
                logger.error(f"Error in collector {collector.name}: {e}")
        
        if total_events > 0:
            logger.info(f"Collection cycle completed: {total_events} total events")
    
    def _store_events(self, events: List[Dict]):
        session = db_manager.get_session()
        try:
            for event_data in events:
                security_event = SecurityEvent(**event_data)
                session.add(security_event)
            
            session.commit()
            logger.debug(f"Stored {len(events)} events to database")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error storing events: {e}")
        finally:
            session.close()
    
    def collect_once(self) -> int:
        total_events = 0
        
        for collector in self.collectors:
            try:
                events = collector.collect()
                if events:
                    self._store_events(events)
                    total_events += len(events)
            except Exception as e:
                logger.error(f"Error in one-time collection from {collector.name}: {e}")
        
        logger.info(f"One-time collection completed: {total_events} events")
        return total_events