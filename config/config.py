import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '1433')
    DB_NAME = os.getenv('DB_NAME', 'SecurityMonitoring')
    DB_USER = os.getenv('DB_USER', 'sa')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    
    # SMTP Configuration
    SMTP_SERVER = os.getenv('SMTP_SERVER')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USER = os.getenv('SMTP_USER')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    
    # API Configuration
    API_PORT = int(os.getenv('API_PORT', '8080'))
    API_SECRET_KEY = os.getenv('API_SECRET_KEY')
    
    # Log Collection Paths
    WINDOWS_EVENT_LOG_PATH = os.getenv('WINDOWS_EVENT_LOG_PATH', r'C:\Windows\System32\winevt\Logs')
    LINUX_SYSLOG_PATH = os.getenv('LINUX_SYSLOG_PATH', '/var/log')
    NETWORK_LOG_PATH = os.getenv('NETWORK_LOG_PATH')
    
    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    
    # Detection Settings
    MAX_EVENTS_PER_MINUTE = 10000
    ALERT_THRESHOLD_HIGH = 8.0
    ALERT_THRESHOLD_MEDIUM = 5.0
    ALERT_THRESHOLD_LOW = 3.0
    
    @property
    def database_url(self):
        # Use SQLite for free, portable database
        return f"sqlite:///security_monitoring.db"