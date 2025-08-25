#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
from pathlib import Path

class ServiceManager:
    def __init__(self):
        self.service_name = "SecurityMonitoringDashboard"
        self.project_root = Path(__file__).parent.parent
        
    def install_windows_service(self):
        try:
            import win32serviceutil
            import win32service
            import win32event
            
            class SecurityMonitorService(win32serviceutil.ServiceFramework):
                _svc_name_ = "SecurityMonitoringDashboard"
                _svc_display_name_ = "Security Monitoring Dashboard"
                _svc_description_ = "Real-time security monitoring and threat detection"
                
                def __init__(self, args):
                    win32serviceutil.ServiceFramework.__init__(self, args)
                    self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                    
                def SvcStop(self):
                    self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                    win32event.SetEvent(self.hWaitStop)
                    
                def SvcDoRun(self):
                    # Start the monitoring system
                    os.chdir(str(self.project_root))
                    from main import SecurityMonitoringSystem
                    
                    system = SecurityMonitoringSystem()
                    system.start_monitoring()
            
            # Install the service
            win32serviceutil.InstallService(
                SecurityMonitorService,
                serviceName=self.service_name,
                displayName="Security Monitoring Dashboard",
                startType=win32service.SERVICE_AUTO_START,
                description="Real-time security monitoring and threat detection system"
            )
            
            print(f"Windows service '{self.service_name}' installed successfully")
            return True
            
        except ImportError:
            print("pywin32 package required for Windows service installation")
            print("Install with: pip install pywin32")
            return False
        except Exception as e:
            print(f"Error installing Windows service: {e}")
            return False
    
    def install_linux_service(self):
        service_content = f"""[Unit]
Description=Security Monitoring Dashboard
After=network.target

[Service]
Type=simple
User=security-monitor
WorkingDirectory={self.project_root}
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONPATH={self.project_root}
ExecStart=/usr/bin/python3 {self.project_root}/main.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        
        service_file = "/etc/systemd/system/security-monitoring.service"
        
        try:
            # Write service file
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Create service user
            subprocess.run(["sudo", "useradd", "-r", "-s", "/bin/false", "security-monitor"], 
                         capture_output=True)
            
            # Set permissions
            subprocess.run(["sudo", "chown", "-R", "security-monitor:security-monitor", 
                          str(self.project_root)], check=True)
            
            # Enable and start service
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", "security-monitoring"], check=True)
            
            print("Linux systemd service installed successfully")
            print("Start with: sudo systemctl start security-monitoring")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error installing Linux service: {e}")
            return False
        except PermissionError:
            print("Permission denied. Run with sudo.")
            return False
    
    def start_service(self):
        if sys.platform == "win32":
            return self._windows_service_action("start")
        else:
            return self._linux_service_action("start")
    
    def stop_service(self):
        if sys.platform == "win32":
            return self._windows_service_action("stop")
        else:
            return self._linux_service_action("stop")
    
    def restart_service(self):
        if sys.platform == "win32":
            return self._windows_service_action("restart")
        else:
            return self._linux_service_action("restart")
    
    def get_service_status(self):
        if sys.platform == "win32":
            return self._windows_service_action("status")
        else:
            return self._linux_service_action("status")
    
    def _windows_service_action(self, action):
        try:
            if action == "start":
                result = subprocess.run(["sc", "start", self.service_name], 
                                      capture_output=True, text=True)
            elif action == "stop":
                result = subprocess.run(["sc", "stop", self.service_name], 
                                      capture_output=True, text=True)
            elif action == "restart":
                subprocess.run(["sc", "stop", self.service_name], capture_output=True)
                subprocess.run(["sc", "start", self.service_name], capture_output=True)
                result = subprocess.run(["sc", "query", self.service_name], 
                                      capture_output=True, text=True)
            elif action == "status":
                result = subprocess.run(["sc", "query", self.service_name], 
                                      capture_output=True, text=True)
            
            print(result.stdout)
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error with Windows service {action}: {e}")
            return False
    
    def _linux_service_action(self, action):
        try:
            result = subprocess.run(["sudo", "systemctl", action, "security-monitoring"], 
                                  capture_output=True, text=True)
            
            if result.stdout:
                print(result.stdout)
            if result.stderr and result.returncode != 0:
                print(result.stderr)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error with Linux service {action}: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Security Monitoring Service Manager')
    parser.add_argument('action', choices=['install', 'start', 'stop', 'restart', 'status'],
                       help='Service action to perform')
    parser.add_argument('--platform', choices=['windows', 'linux'], 
                       help='Target platform (auto-detected if not specified)')
    
    args = parser.parse_args()
    
    service_manager = ServiceManager()
    
    if args.action == 'install':
        if sys.platform == "win32":
            success = service_manager.install_windows_service()
        else:
            success = service_manager.install_linux_service()
    elif args.action == 'start':
        success = service_manager.start_service()
    elif args.action == 'stop':
        success = service_manager.stop_service()
    elif args.action == 'restart':
        success = service_manager.restart_service()
    elif args.action == 'status':
        success = service_manager.get_service_status()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())