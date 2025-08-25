#!/usr/bin/env python3
"""
Quick Demo Script for Security Monitoring Dashboard
Perfect for showcasing the project to recruiters and on GitHub
"""

import subprocess
import time
import sys
import os

def print_banner():
    print("""
SECURITY MONITORING DASHBOARD - DEMO
=====================================
A free, open-source SIEM solution built with Python

Features demonstrated:
  - Real-time security event processing
  - MITRE ATT&CK threat detection
  - Interactive web dashboard
  - Behavioral analytics engine
  - Incident correlation system
""")

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    try:
        import pandas
        import plotly
        import dash
        print("✓ All dependencies installed")
        return True
    except ImportError as e:
        print(f"X Missing dependency: {e}")
        print("Run: pip install -r requirements.txt")
        return False

def setup_demo_database():
    """Initialize database and generate demo data"""
    print("Setting up demo database...")
    
    try:
        # Initialize database
        from src.database.database import db_manager
        db_manager.create_tables()
        print("✓ Database initialized")
        
        # Generate demo data
        from demo.demo_data_generator import DemoDataGenerator
        generator = DemoDataGenerator()
        generator.populate_database(events_count=1500, days_back=14)
        print("✓ Demo data generated (1,500 security events)")
        
        return True
    except Exception as e:
        print(f"X Database setup failed: {e}")
        return False

def start_dashboard():
    """Start the web dashboard"""
    print("🚀 Starting web dashboard...")
    print("📱 Dashboard URL: http://localhost:8050")
    print("⏱️  Loading... (this may take 30 seconds)")
    
    try:
        # Import and start dashboard
        from web_dashboard import app
        print("✅ Dashboard ready!")
        print("\n🎯 DEMO FEATURES TO SHOWCASE:")
        print("   • Real-time KPI metrics")
        print("   • Security events timeline") 
        print("   • Top risk users analysis")
        print("   • Recent incidents table")
        print("   • Auto-refresh every 30 seconds")
        print("\n💡 Press Ctrl+C to stop the demo\n")
        
        app.run_server(debug=False, host='0.0.0.0', port=8050)
        
    except KeyboardInterrupt:
        print("\n👋 Demo stopped. Thanks for viewing!")
    except Exception as e:
        print(f"❌ Dashboard failed to start: {e}")
        return False
    
    return True

def generate_sample_reports():
    """Generate sample reports to showcase analytics"""
    print("📈 Generating sample reports...")
    
    try:
        from src.dashboard.report_generator import SecurityReportGenerator
        report_gen = SecurityReportGenerator()
        
        # Executive summary
        executive_report = report_gen.generate_executive_summary(days=7)
        print(f"✅ Executive Summary: {executive_report['incident_statistics']['total_incidents']} incidents analyzed")
        
        # User risk report  
        user_risk = report_gen.generate_user_risk_report(top_n=10)
        print(f"✅ User Risk Analysis: {len(user_risk['top_risk_users'])} users profiled")
        
        return True
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return False

def run_compliance_demo():
    """Demo compliance monitoring features"""
    print("📋 Running compliance checks...")
    
    try:
        from src.compliance.compliance_monitor import ComplianceMonitor
        monitor = ComplianceMonitor()
        
        # PCI-DSS compliance check
        pci_result = monitor.evaluate_compliance('PCI-DSS', period_days=7)
        print(f"✅ PCI-DSS Compliance: {pci_result['compliance_score']:.1f}%")
        
        return True
    except Exception as e:
        print(f"❌ Compliance check failed: {e}")
        return False

def main():
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Setup demo environment
    if not setup_demo_database():
        sys.exit(1)
    
    # Generate reports
    generate_sample_reports()
    
    # Run compliance demo
    run_compliance_demo()
    
    print("\n🎉 DEMO SETUP COMPLETE!")
    print("="*50)
    
    # Start interactive dashboard
    start_dashboard()

if __name__ == "__main__":
    main()