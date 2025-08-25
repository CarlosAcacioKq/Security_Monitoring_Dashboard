#!/usr/bin/env python3
"""Simple test to verify dashboard functionality"""

print("Testing Security Monitoring Dashboard...")

try:
    from web_dashboard import get_kpi_data, get_events_timeline
    
    # Test KPI data
    kpis = get_kpi_data()
    print(f"KPI Data: {kpis['total_events']} total events, {kpis['high_risk_events']} high risk")
    
    # Test timeline data
    timeline = get_events_timeline()
    print(f"Timeline Data: {len(timeline)} data points")
    
    print("All dashboard components working!")
    print("Ready for GitHub showcase!")
    
except Exception as e:
    print(f"X Error: {e}")
    
print("\nTo start the web dashboard, run: python web_dashboard.py")