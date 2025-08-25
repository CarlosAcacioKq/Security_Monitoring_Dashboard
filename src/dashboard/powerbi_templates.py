from typing import Dict, List
import json

class PowerBITemplateGenerator:
    def __init__(self):
        self.template_configs = {
            'executive_dashboard': self._executive_dashboard_config(),
            'analyst_dashboard': self._analyst_dashboard_config(),
            'compliance_dashboard': self._compliance_dashboard_config()
        }
    
    def _executive_dashboard_config(self) -> Dict:
        return {
            'name': 'Executive Security Dashboard',
            'description': 'High-level security metrics for executive reporting',
            'data_sources': [
                {
                    'name': 'SecurityEvents',
                    'connection_string': 'SQL Server connection to security_events table',
                    'refresh_schedule': 'Every 15 minutes'
                },
                {
                    'name': 'Incidents',
                    'connection_string': 'SQL Server connection to incidents table',
                    'refresh_schedule': 'Every 5 minutes'
                }
            ],
            'visualizations': [
                {
                    'type': 'KPI Card',
                    'title': 'Open Critical Incidents',
                    'measure': 'COUNT(incidents[id]) WHERE severity = "critical" AND status = "open"',
                    'position': {'row': 1, 'column': 1}
                },
                {
                    'type': 'KPI Card',
                    'title': 'Events Last 24H',
                    'measure': 'COUNT(security_events[id]) WHERE timestamp >= TODAY()-1',
                    'position': {'row': 1, 'column': 2}
                },
                {
                    'type': 'KPI Card',
                    'title': 'Mean Time to Detection',
                    'measure': 'AVERAGE(incidents[detection_time_hours])',
                    'position': {'row': 1, 'column': 3}
                },
                {
                    'type': 'Line Chart',
                    'title': 'Security Events Trend (30 Days)',
                    'x_axis': 'security_events[timestamp]',
                    'y_axis': 'COUNT(security_events[id])',
                    'position': {'row': 2, 'column': 1, 'span': 2}
                },
                {
                    'type': 'Donut Chart',
                    'title': 'Incidents by Severity',
                    'values': 'incidents[severity]',
                    'position': {'row': 2, 'column': 3}
                },
                {
                    'type': 'Bar Chart',
                    'title': 'Top MITRE Techniques',
                    'x_axis': 'security_events[mitre_technique]',
                    'y_axis': 'COUNT(security_events[id])',
                    'position': {'row': 3, 'column': 1, 'span': 2}
                },
                {
                    'type': 'Table',
                    'title': 'Recent Critical Incidents',
                    'columns': ['incident_id', 'title', 'created_timestamp', 'risk_score'],
                    'filter': 'incidents[severity] = "critical"',
                    'position': {'row': 3, 'column': 3}
                }
            ]
        }
    
    def _analyst_dashboard_config(self) -> Dict:
        return {
            'name': 'Security Analyst Dashboard',
            'description': 'Detailed operational view for security analysts',
            'data_sources': [
                {
                    'name': 'SecurityEvents',
                    'connection_string': 'SQL Server connection to security_events table',
                    'refresh_schedule': 'Every 1 minute'
                },
                {
                    'name': 'ThreatIntelligence',
                    'connection_string': 'SQL Server connection to threat_intelligence table',
                    'refresh_schedule': 'Every 30 minutes'
                }
            ],
            'visualizations': [
                {
                    'type': 'Real-time Feed',
                    'title': 'Live Security Events',
                    'data_source': 'security_events',
                    'columns': ['timestamp', 'event_type', 'user_id', 'source_ip', 'risk_score'],
                    'filter': 'timestamp >= NOW()-1H',
                    'position': {'row': 1, 'column': 1, 'span': 3}
                },
                {
                    'type': 'Heat Map',
                    'title': 'Attack Sources (Geographic)',
                    'x_axis': 'security_events[source_ip_country]',
                    'y_axis': 'security_events[source_ip_city]',
                    'values': 'COUNT(security_events[id])',
                    'position': {'row': 2, 'column': 1}
                },
                {
                    'type': 'Timeline',
                    'title': 'Incident Timeline',
                    'time_axis': 'incidents[created_timestamp]',
                    'events': 'incidents[title]',
                    'position': {'row': 2, 'column': 2, 'span': 2}
                },
                {
                    'type': 'Scatter Plot',
                    'title': 'User Risk vs Activity',
                    'x_axis': 'AVG(security_events[risk_score]) BY user_id',
                    'y_axis': 'COUNT(security_events[id]) BY user_id',
                    'position': {'row': 3, 'column': 1}
                },
                {
                    'type': 'Funnel Chart',
                    'title': 'Detection Pipeline',
                    'stages': ['Total Events', 'High Risk Events', 'Correlated Events', 'Incidents', 'Investigated'],
                    'position': {'row': 3, 'column': 2}
                },
                {
                    'type': 'Network Diagram',
                    'title': 'Network Traffic Patterns',
                    'nodes': 'security_events[source_ip], security_events[destination_ip]',
                    'edges': 'security_events connections',
                    'position': {'row': 3, 'column': 3}
                }
            ]
        }
    
    def _compliance_dashboard_config(self) -> Dict:
        return {
            'name': 'Compliance Dashboard',
            'description': 'Regulatory compliance monitoring and reporting',
            'data_sources': [
                {
                    'name': 'ComplianceEvents',
                    'connection_string': 'SQL Server connection to compliance_events table',
                    'refresh_schedule': 'Every 30 minutes'
                }
            ],
            'visualizations': [
                {
                    'type': 'Gauge',
                    'title': 'PCI-DSS Compliance Score',
                    'measure': 'compliance_score_calculation()',
                    'min_value': 0,
                    'max_value': 100,
                    'position': {'row': 1, 'column': 1}
                },
                {
                    'type': 'Gauge',
                    'title': 'SOX Compliance Score',
                    'measure': 'sox_compliance_score_calculation()',
                    'min_value': 0,
                    'max_value': 100,
                    'position': {'row': 1, 'column': 2}
                },
                {
                    'type': 'Waterfall Chart',
                    'title': 'Compliance Score Breakdown',
                    'categories': 'compliance_events[control_id]',
                    'values': 'compliance_impact_calculation()',
                    'position': {'row': 1, 'column': 3}
                },
                {
                    'type': 'Calendar Heatmap',
                    'title': 'Daily Compliance Status',
                    'date_axis': 'compliance_events[timestamp]',
                    'values': 'compliance_events[status]',
                    'position': {'row': 2, 'column': 1, 'span': 2}
                },
                {
                    'type': 'Matrix',
                    'title': 'Control Status Matrix',
                    'rows': 'compliance_events[compliance_framework]',
                    'columns': 'compliance_events[control_id]',
                    'values': 'compliance_events[status]',
                    'position': {'row': 2, 'column': 3}
                },
                {
                    'type': 'Table',
                    'title': 'Recent Compliance Violations',
                    'columns': ['timestamp', 'compliance_framework', 'control_id', 'details'],
                    'filter': 'status = "fail"',
                    'position': {'row': 3, 'column': 1, 'span': 3}
                }
            ]
        }
    
    def generate_powerbi_pbix_template(self, dashboard_type: str) -> str:
        if dashboard_type not in self.template_configs:
            raise ValueError(f"Unknown dashboard type: {dashboard_type}")
        
        config = self.template_configs[dashboard_type]
        
        # Generate PowerBI template JSON (simplified)
        template = {
            'version': '1.0',
            'config': config,
            'sql_queries': self._generate_sql_queries(config),
            'dax_measures': self._generate_dax_measures(config)
        }
        
        filename = f"powerbi_template_{dashboard_type}.json"
        filepath = f"src/dashboard/templates/{filename}"
        
        import os
        os.makedirs('src/dashboard/templates', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(template, f, indent=2)
        
        logger.info(f"PowerBI template generated: {filepath}")
        return filepath
    
    def _generate_sql_queries(self, config: Dict) -> Dict[str, str]:
        queries = {}
        
        # Executive dashboard queries
        if 'executive' in config['name'].lower():
            queries['incident_summary'] = """
                SELECT 
                    severity,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk_score
                FROM incidents 
                WHERE created_timestamp >= DATEADD(day, -7, GETDATE())
                GROUP BY severity
            """
            
            queries['event_volume'] = """
                SELECT 
                    CAST(timestamp AS DATE) as date,
                    COUNT(*) as event_count,
                    AVG(risk_score) as avg_risk_score
                FROM security_events 
                WHERE timestamp >= DATEADD(day, -30, GETDATE())
                GROUP BY CAST(timestamp AS DATE)
                ORDER BY date
            """
        
        # Analyst dashboard queries
        elif 'analyst' in config['name'].lower():
            queries['real_time_events'] = """
                SELECT TOP 100
                    timestamp,
                    event_type,
                    user_id,
                    source_ip,
                    hostname,
                    risk_score,
                    mitre_technique
                FROM security_events 
                WHERE timestamp >= DATEADD(hour, -1, GETDATE())
                ORDER BY timestamp DESC
            """
            
            queries['user_risk_analysis'] = """
                SELECT 
                    user_id,
                    COUNT(*) as total_events,
                    AVG(risk_score) as avg_risk_score,
                    MAX(risk_score) as max_risk_score
                FROM security_events 
                WHERE timestamp >= DATEADD(day, -30, GETDATE())
                    AND user_id IS NOT NULL
                GROUP BY user_id
                ORDER BY avg_risk_score DESC
            """
        
        return queries
    
    def _generate_dax_measures(self, config: Dict) -> Dict[str, str]:
        measures = {}
        
        # Common DAX measures
        measures['Total Events'] = "COUNTROWS(security_events)"
        measures['High Risk Events'] = "COUNTROWS(FILTER(security_events, security_events[risk_score] >= 6))"
        measures['Average Risk Score'] = "AVERAGE(security_events[risk_score])"
        measures['Open Incidents'] = "COUNTROWS(FILTER(incidents, incidents[status] = \"open\"))"
        measures['Critical Incidents'] = "COUNTROWS(FILTER(incidents, incidents[severity] = \"critical\"))"
        
        # Time-based measures
        measures['Events Last 24H'] = """
            COUNTROWS(
                FILTER(
                    security_events,
                    security_events[timestamp] >= NOW() - 1
                )
            )
        """
        
        measures['Incident Trend'] = """
            VAR CurrentPeriod = COUNTROWS(incidents)
            VAR PreviousPeriod = CALCULATE(
                COUNTROWS(incidents),
                DATEADD(incidents[created_timestamp], -7, DAY)
            )
            RETURN DIVIDE(CurrentPeriod - PreviousPeriod, PreviousPeriod, 0)
        """
        
        return measures