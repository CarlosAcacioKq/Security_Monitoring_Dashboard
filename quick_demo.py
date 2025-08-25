#!/usr/bin/env python3
"""
Quick Demo Script for Security Monitoring Dashboard
Perfect for showcasing the project to recruiters and on GitHub
"""

import sys
import os

def main():
    print("\n" + "="*50)
    print("SECURITY MONITORING DASHBOARD - DEMO")
    print("="*50)
    print("A free, open-source SIEM solution built with Python\n")
    
    print("Setting up demo environment...")
    
    try:
        # Initialize database
        from src.database.database import db_manager
        try:
            db_manager.create_tables()
            print("Database initialized successfully")
        except Exception:
            print("Database already exists - continuing...")
        
        # Generate demo data
        from demo.demo_data_generator import DemoDataGenerator
        generator = DemoDataGenerator()
        generator.populate_database(events_count=1000, days_back=14)
        print("Demo data generated (1,000 security events)")
        
        # Start web dashboard
        print("\nStarting web dashboard...")
        print("Dashboard URL: http://localhost:8050")
        print("Loading dashboard... (please wait)")
        
        from web_dashboard import app
        print("\nDashboard ready! Features available:")
        print("- Real-time KPI metrics")
        print("- Security events timeline") 
        print("- Top risk users analysis")
        print("- Recent incidents table")
        print("- Auto-refresh every 30 seconds")
        print("\nPress Ctrl+C to stop the demo\n")
        
        app.run_server(debug=False, host='0.0.0.0', port=8050)
        
    except KeyboardInterrupt:
        print("\nDemo stopped. Thanks for viewing!")
    except Exception as e:
        print(f"Error: {e}")
        print("Please ensure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)

if __name__ == "__main__":
    main()